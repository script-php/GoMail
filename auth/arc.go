package auth

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ed25519"
)

// ARCAuthenticationResults builds the ARC-Authentication-Results header
// Records SPF, DKIM, and DMARC results at this hop
func ARCAuthenticationResults(hostname string, spfResult, dkimResult, dmarcResult string) string {
	return fmt.Sprintf("ARC-Authentication-Results: i=1; %s;\r\n\tspf=%s;\r\n\tdkim=%s;\r\n\tdmarc=%s",
		hostname, spfResult, dkimResult, dmarcResult)
}

// ARCMessageSignatureInput represents data for ARC-Message-Signature generation
type ARCMessageSignatureInput struct {
	Instance      int           // i= value (typically 1 for first hop)
	Selector      string        // s= (selector)
	Domain        string        // d= (domain)
	PrivateKey    crypto.Signer // RSA or Ed25519 private key
	Message       []byte        // Full message (headers + body) for header extraction
	BodyHash      string        // base64-encoded SHA256 hash of body
}

// getAlgorithm returns the algorithm name based on key type
func getAlgorithm(privKey crypto.Signer) string {
	switch privKey.(type) {
	case *rsa.PrivateKey:
		return "rsa-sha256"
	case ed25519.PrivateKey:
		return "ed25519-sha256"
	default:
		return "rsa-sha256" // default
	}
}

// ARCMessageSignature generates the ARC-Message-Signature header
// Supports both RSA-2048 and Ed25519 keys
func ARCMessageSignature(input *ARCMessageSignatureInput) (string, error) {
	if input.PrivateKey == nil {
		return "", fmt.Errorf("private key required")
	}

	algorithm := getAlgorithm(input.PrivateKey)

	// Parse headers from message to find actual headers to include
	allHeaders, _, _ := parseMessageHeaders(input.Message)

	// List of headers to include in signature (order matters)
	headersToSign := []string{"from", "to", "subject", "date", "message-id"}

	// Build the canonical header data by extracting and canonicalizing each header
	// Use the exact raw header line as it appears in the message
	var dataToSign bytes.Buffer
	for _, headerName := range headersToSign {
		// Find this header in the message
		for _, h := range allHeaders {
			if strings.EqualFold(h.key, headerName) {
				// Use raw header line and apply relaxed canonicalization
				canonical, _ := relaxedCanonicalHeader(string(h.raw))
				dataToSign.WriteString(canonical)
				dataToSign.WriteString("\r\n")
				break
			}
		}
	}

	// Build signature tags (b= is empty during signing)
	sigTags := []string{
		fmt.Sprintf("i=%d", input.Instance),
		fmt.Sprintf("a=%s", algorithm),
		"c=relaxed/relaxed",
		fmt.Sprintf("d=%s", input.Domain),
		fmt.Sprintf("s=%s", input.Selector),
		"h=" + strings.Join(headersToSign, ":"),
		fmt.Sprintf("bh=%s", input.BodyHash),
		"b=", // Empty during signing
	}

	// Add the signature field itself (without trailing CRLF)
	sigHeader := strings.Join(sigTags, "; ")
	canonical, _ := relaxedCanonicalHeader("ARC-Message-Signature: " + sigHeader)
	dataToSign.WriteString(canonical)

	// Sign the data
	hash := sha256.Sum256(dataToSign.Bytes())
	signature, err := input.PrivateKey.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	// Replace empty b= with actual signature
	encodedSig := base64.StdEncoding.EncodeToString(signature)
	sigTags[len(sigTags)-1] = fmt.Sprintf("b=%s", encodedSig)

	return fmt.Sprintf("ARC-Message-Signature: %s", strings.Join(sigTags, "; ")), nil
}

// ARCSealInput represents data for ARC-Seal generation
type ARCSealInput struct {
	Instance              int           // i= value
	Selector              string        // s=
	Domain                string        // d=
	PrivateKey            crypto.Signer // RSA or Ed25519 private key
	AuthenticationResults string        // Full ARC-Authentication-Results header line (including header name)
	MessageSignature      string        // Full ARC-Message-Signature header line (including header name)
	Timestamp             time.Time
	CVValue               string // cv= value (none, pass, fail)
}

// ARCSeal generates the ARC-Seal header per RFC 8617 Section 5.1.1.
// The ARC-Seal does NOT sign regular message headers.
// It only covers the ARC header set: ARC-Authentication-Results,
// ARC-Message-Signature, and the ARC-Seal itself (with b= empty).
// The ARC-Seal does NOT have an h= tag.
func ARCSeal(input *ARCSealInput) (string, error) {
	if input.PrivateKey == nil {
		return "", fmt.Errorf("private key required")
	}

	timestamp := input.Timestamp.Unix()
	algorithm := getAlgorithm(input.PrivateKey)

	// Default cv value if not set
	cvValue := input.CVValue
	if cvValue == "" {
		cvValue = "none" // Default for i=1
	}

	// Build seal tags (b= is empty during signing)
	// Per RFC 8617: ARC-Seal does NOT have an h= tag
	sealTags := []string{
		fmt.Sprintf("i=%d", input.Instance),
		fmt.Sprintf("a=%s", algorithm),
		fmt.Sprintf("t=%d", timestamp),
		fmt.Sprintf("cv=%s", cvValue),
		fmt.Sprintf("d=%s", input.Domain),
		fmt.Sprintf("s=%s", input.Selector),
		"b=", // Empty during signing
	}

	// Per RFC 8617 Section 5.1.1: For instance i, the data to sign is
	// all ARC header fields for instances 1..i in order, with ARC-Seal
	// for the current instance last (with b= empty).
	//
	// For i=1 the order is:
	//   ARC-Authentication-Results: i=1
	//   ARC-Message-Signature: i=1
	//   ARC-Seal: i=1 (b= empty) -- no trailing CRLF
	var dataToSign bytes.Buffer

	// 1. ARC-Authentication-Results (canonicalized)
	canonical, _ := relaxedCanonicalHeader(input.AuthenticationResults)
	dataToSign.WriteString(canonical)
	dataToSign.WriteString("\r\n")

	// 2. ARC-Message-Signature (canonicalized, including its full b= value)
	canonical, _ = relaxedCanonicalHeader(input.MessageSignature)
	dataToSign.WriteString(canonical)
	dataToSign.WriteString("\r\n")

	// 3. ARC-Seal itself (canonicalized, b= empty, NO trailing CRLF)
	sealHeader := "ARC-Seal: " + strings.Join(sealTags, "; ")
	canonical, _ = relaxedCanonicalHeader(sealHeader)
	dataToSign.WriteString(canonical)

	// Sign the data
	hash := sha256.Sum256(dataToSign.Bytes())
	signature, err := input.PrivateKey.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("seal signing failed: %w", err)
	}

	// Replace empty b= with actual signature
	encodedSig := base64.StdEncoding.EncodeToString(signature)
	sealTags[len(sealTags)-1] = fmt.Sprintf("b=%s", encodedSig)

	return fmt.Sprintf("ARC-Seal: %s", strings.Join(sealTags, "; ")), nil
}

// BodyHash computes the base64-encoded SHA256 hash of email body for ARC
// Uses relaxed canonicalization per RFC 6376
func BodyHash(body string) string {
	// Convert to bytes and canonicalize using relaxed method
	bodyBytes := []byte(body)
	// Call the relaxed body hash function
	hash := bodyHashFunc(false, bodyBytes) // false = not simple, so use relaxed
	return base64.StdEncoding.EncodeToString(hash)
}

// ARCChainSigner generates all three ARC headers in the correct order
// Supports any instance number (1 for initial, 2+ for forwarding)
// Returns: [authResults, messageSignature, seal] or error
func ARCChainSigner(domain, selector string, privKey crypto.Signer, spf, dkim, dmarc, hostname string, bodyContent string, instance int) ([]string, error) {
	if privKey == nil {
		return nil, fmt.Errorf("private key required for ARC signing")
	}

	// Extract just the body from the full message for body hash calculation
	// bodyContent contains the entire message (headers + body)
	msgBytes := []byte(bodyContent)
	headerEnd := bytes.Index(msgBytes, []byte("\r\n\r\n"))
	separatorLen := 4
	if headerEnd == -1 {
		headerEnd = bytes.Index(msgBytes, []byte("\n\n"))
		separatorLen = 2
		if headerEnd == -1 {
			return nil, fmt.Errorf("no header/body boundary found in message")
		}
	}
	
	bodyOnly := msgBytes[headerEnd+separatorLen:]

	// 1. Generate Authentication Results (full header line)
	authResultsHeader := fmt.Sprintf("ARC-Authentication-Results: i=%d; %s;\r\n\tspf=%s;\r\n\tdkim=%s;\r\n\tdmarc=%s",
		instance, hostname, spf, dkim, dmarc)

	// 2. Generate Message Signature using the full message for header extraction
	bodyHash := BodyHash(string(bodyOnly))
	msgSigInput := &ARCMessageSignatureInput{
		Instance:   instance,
		Selector:   selector,
		Domain:     domain,
		PrivateKey: privKey,
		Message:    msgBytes, // Pass full message for header extraction
		BodyHash:   bodyHash,
	}
	msgSig, err := ARCMessageSignature(msgSigInput)
	if err != nil {
		return nil, fmt.Errorf("generating ARC-Message-Signature: %w", err)
	}

	// 3. Generate Seal - determine cv= based on instance
	// cv=none for first entry (i=1)
	// cv=pass/fail for subsequent entries (i=2+)
	cvValue := "none"
	if instance > 1 {
		cvValue = "pass" // In real implementation, would validate previous chain
	}

	sealInput := &ARCSealInput{
		Instance:              instance,
		Selector:              selector,
		Domain:                domain,
		PrivateKey:            privKey,
		AuthenticationResults: authResultsHeader, // Full header line with header name
		MessageSignature:      msgSig,            // Full header line with header name
		Timestamp:             time.Now(),
		CVValue:               cvValue,
	}
	seal, err := ARCSeal(sealInput)
	if err != nil {
		return nil, fmt.Errorf("generating ARC-Seal: %w", err)
	}

	return []string{authResultsHeader, msgSig, seal}, nil
}

// ExtractArcHeaders pulls all ARC headers from raw message
// Returns map of instance -> {authResults, msgSig, seal}
func ExtractArcHeaders(rawMessage []byte) map[int]map[string]string {
	headers := make(map[int]map[string]string)
	lines := strings.Split(string(rawMessage), "\r\n")
	
	currentInstance := 0
	var currentType string
	var currentValue strings.Builder

	for _, line := range lines {
		// Stop at blank line (end of headers)
		if line == "" {
			// Save last header if any
			if currentType != "" && currentInstance > 0 {
				if _, exists := headers[currentInstance]; !exists {
					headers[currentInstance] = make(map[string]string)
				}
				headers[currentInstance][currentType] = currentValue.String()
			}
			break
		}

		// Check for ARC header (case-insensitive)
		upperLine := strings.ToUpper(line)
		
		// Check if this is a new ARC header line (not a continuation)
		isNewArcHeader := strings.HasPrefix(upperLine, "ARC-AUTHENTICATION-RESULTS:") ||
			strings.HasPrefix(upperLine, "ARC-MESSAGE-SIGNATURE:") ||
			strings.HasPrefix(upperLine, "ARC-SEAL:")
		
		if isNewArcHeader {
			// Save previous header if one was being accumulated
			if currentType != "" && currentInstance > 0 {
				if _, exists := headers[currentInstance]; !exists {
					headers[currentInstance] = make(map[string]string)
				}
				headers[currentInstance][currentType] = currentValue.String()
			}
			
			// Determine which ARC header type this is
			if strings.HasPrefix(upperLine, "ARC-AUTHENTICATION-RESULTS:") {
				currentType = "auth-results"
			} else if strings.HasPrefix(upperLine, "ARC-MESSAGE-SIGNATURE:") {
				currentType = "message-signature"
			} else if strings.HasPrefix(upperLine, "ARC-SEAL:") {
				currentType = "seal"
			}
			
			// Extract instance number from i= tag
			if idx := strings.Index(line, "i="); idx >= 0 {
				fmt.Sscanf(line[idx:], "i=%d", &currentInstance)
			}
			
			// Start accumulating this header's value
			currentValue.Reset()
			currentValue.WriteString(line)
		} else if currentType != "" && (strings.HasPrefix(line, "\t") || strings.HasPrefix(line, " ")) {
			// This is a continuation line (folded header)
			currentValue.WriteString("\r\n")
			currentValue.WriteString(line)
		}
	}

	return headers
}

// GetHighestArcInstance returns the highest i= value from existing ARC headers
// Returns 0 if no ARC headers found, used to determine next instance number
func GetHighestArcInstance(rawMessage []byte) int {
	arcHeaders := ExtractArcHeaders(rawMessage)
	
	maxInstance := 0
	for instance := range arcHeaders {
		if instance > maxInstance {
			maxInstance = instance
		}
	}
	
	return maxInstance
}

// ARCValidationResult holds the result of ARC chain validation
type ARCValidationResult struct {
	IsValid      bool
	Status       string // pass, fail, permerror, temperror, none
	HighestValid int    // Highest valid instance in chain
	Details      string // Human-readable details
}

// verifyARCMessageSignature verifies the ARC-Message-Signature header signature
// Similar to DKIM verification but specific to ARC-Message-Signature tags
// Returns: (isValid, errorDetail)
func verifyARCMessageSignature(rawMessage []byte, arcMsgSig string, pubKeyRecord *DKIMRecord) (bool, string) {
	if arcMsgSig == "" {
		return false, "empty message-signature"
	}

	// Parse ARC-Message-Signature tags
	tags := parseDKIMTags(arcMsgSig)
	
	algo := tags["a"]
	headersToVerify := tags["h"]
	bodyHashB64 := tags["bh"]
	sigB64 := tags["b"]
	canonMethod := tags["c"]

	if sigB64 == "" {
		return false, "missing b= in ARC-Message-Signature"
	}

	// Parse canonicalization (default: relaxed/relaxed for ARC)
	headerSimple := false
	bodySimple := false
	if canonMethod != "" {
		parts := strings.Split(canonMethod, "/")
		if len(parts) >= 1 {
			headerSimple = strings.EqualFold(strings.TrimSpace(parts[0]), "simple")
		}
		if len(parts) >= 2 {
			bodySimple = strings.EqualFold(strings.TrimSpace(parts[1]), "simple")
		}
	}

	// Extract body and verify body hash
	hdrs, bodyOffset, err := parseMessageHeaders(rawMessage)
	if err != nil {
		return false, fmt.Sprintf("failed to parse message: %v", err)
	}
	
	body := rawMessage[bodyOffset:]
	bodyHash := bodyHashFunc(bodySimple, body)
	expectedBH := base64.StdEncoding.EncodeToString(bodyHash)
	if bodyHashB64 != expectedBH {
		return false, fmt.Sprintf("body hash mismatch: expected %s, got %s", bodyHashB64, expectedBH)
	}

	// Build data to sign (similar to DKIM)
	revHdrs := make(map[string][]*headerRaw)
	for _, h := range hdrs {
		lkey := strings.ToLower(h.key)
		revHdrs[lkey] = append([]*headerRaw{h}, revHdrs[lkey]...)
	}

	var dataToSign bytes.Buffer
	headersToSign := strings.Split(headersToVerify, ":")

	for _, headerName := range headersToSign {
		headerName = strings.TrimSpace(headerName)
		lkey := strings.ToLower(headerName)

		hdrsForKey := revHdrs[lkey]
		if len(hdrsForKey) == 0 {
			continue
		}

		h := hdrsForKey[0]
		revHdrs[lkey] = hdrsForKey[1:]

		hval := string(h.raw)
		if !headerSimple {
			hval, _ = relaxedCanonicalHeader(hval)
		}

		dataToSign.WriteString(hval)
		dataToSign.WriteString("\r\n")
	}

	// Strip b= value from ARC-Message-Signature before signing
	arcMsgSigStripped := stripDKIMBValue(arcMsgSig)
	sigVal := "ARC-Message-Signature: " + arcMsgSigStripped
	if !headerSimple {
		sigVal, _ = relaxedCanonicalHeader(sigVal)
	}
	dataToSign.WriteString(sigVal)

	// Verify signature
	hash := sha256.Sum256(dataToSign.Bytes())
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, fmt.Sprintf("invalid signature encoding: %v", err)
	}

	// Extract public key from RawKey field
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyRecord.RawKey)
	if err != nil {
		return false, fmt.Sprintf("invalid public key encoding: %v", err)
	}

	// Verify based on algorithm
	switch {
	case strings.Contains(algo, "ed25519"):
		key, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err == nil {
			if edPub, ok := key.(ed25519.PublicKey); ok {
				if ed25519.Verify(edPub, hash[:], sigBytes) {
					return true, ""
				}
			}
		} else if len(pubKeyBytes) == ed25519.PublicKeySize {
			if ed25519.Verify(ed25519.PublicKey(pubKeyBytes), hash[:], sigBytes) {
				return true, ""
			}
		}
		return false, "ed25519 signature verification failed"

	case strings.Contains(algo, "rsa"):
		key, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err != nil {
			return false, fmt.Sprintf("cannot parse RSA public key: %v", err)
		}
		rsaPub, ok := key.(*rsa.PublicKey)
		if !ok {
			return false, "key is not RSA"
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sigBytes); err != nil {
			return false, fmt.Sprintf("RSA signature verification failed: %v", err)
		}
		return true, ""
	}

	return false, fmt.Sprintf("unsupported algorithm: %s", algo)
}

// verifyARCSeal verifies the ARC-Seal header signature
// ARC-Seal signs all three ARC headers (Authentication-Results, Message-Signature, Seal itself)
// Returns: (isValid, errorDetail)
func verifyARCSeal(arcAuthResults, arcMsgSig, arcSeal string, pubKeyRecord *DKIMRecord) (bool, string) {
	if arcSeal == "" {
		return false, "empty seal"
	}

	// Parse ARC-Seal tags
	tags := parseDKIMTags(arcSeal)
	
	algo := tags["a"]
	sigB64 := tags["b"]
	canonMethod := tags["c"]

	if sigB64 == "" {
		return false, "missing b= in ARC-Seal"
	}

	// Parse canonicalization (ARC-Seal typically uses relaxed/relaxed)
	headerSimple := false
	if canonMethod != "" {
		parts := strings.Split(canonMethod, "/")
		if len(parts) >= 1 {
			headerSimple = strings.EqualFold(strings.TrimSpace(parts[0]), "simple")
		}
	}

	// Build data to sign: ARC-Authentication-Results, ARC-Message-Signature, ARC-Seal (with b= empty)
	var dataToSign bytes.Buffer

	// Add ARC-Authentication-Results (without "ARC-Authentication-Results: " prefix if it has it)
	authLine := arcAuthResults
	if strings.HasPrefix(strings.ToUpper(authLine), "ARC-AUTHENTICATION-RESULTS:") {
		authLine = authLine[len("ARC-Authentication-Results:"):]
		authLine = "ARC-Authentication-Results:" + authLine
	}
	if !headerSimple {
		authLine, _ = relaxedCanonicalHeader(authLine)
	}
	dataToSign.WriteString(authLine)
	dataToSign.WriteString("\r\n")

	// Add ARC-Message-Signature
	msgSigLine := arcMsgSig
	if !headerSimple {
		msgSigLine, _ = relaxedCanonicalHeader(msgSigLine)
	}
	dataToSign.WriteString(msgSigLine)
	dataToSign.WriteString("\r\n")

	// Add ARC-Seal with b= stripped
	sealLine := stripDKIMBValue(arcSeal)
	sealLine = "ARC-Seal: " + sealLine
	if !headerSimple {
		sealLine, _ = relaxedCanonicalHeader(sealLine)
	}
	dataToSign.WriteString(sealLine)

	// Verify signature
	hash := sha256.Sum256(dataToSign.Bytes())
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, fmt.Sprintf("invalid signature encoding: %v", err)
	}

	// Extract public key from RawKey field
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyRecord.RawKey)
	if err != nil {
		return false, fmt.Sprintf("invalid public key encoding: %v", err)
	}

	// Verify based on algorithm
	switch {
	case strings.Contains(algo, "ed25519"):
		key, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err == nil {
			if edPub, ok := key.(ed25519.PublicKey); ok {
				if ed25519.Verify(edPub, hash[:], sigBytes) {
					return true, ""
				}
			}
		} else if len(pubKeyBytes) == ed25519.PublicKeySize {
			if ed25519.Verify(ed25519.PublicKey(pubKeyBytes), hash[:], sigBytes) {
				return true, ""
			}
		}
		return false, "ed25519 signature verification failed"

	case strings.Contains(algo, "rsa"):
		key, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err != nil {
			return false, fmt.Sprintf("cannot parse RSA public key: %v", err)
		}
		rsaPub, ok := key.(*rsa.PublicKey)
		if !ok {
			return false, "key is not RSA"
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sigBytes); err != nil {
			return false, fmt.Sprintf("RSA signature verification failed: %v", err)
		}
		return true, ""
	}

	return false, fmt.Sprintf("unsupported algorithm: %s", algo)
}

// ValidateArcChainAtInstance validates the ARC chain up to a specific instance
// Performs full cryptographic validation of signatures and chain integrity
// Returns: (isValid, status, error)
func ValidateArcChainAtInstance(rawMessage []byte, instance int) (bool, string, error) {
	arcHeaders := ExtractArcHeaders(rawMessage)
	
	// Check if this instance exists
	if arcHeaders[instance] == nil {
		return false, "permerror", fmt.Errorf("no ARC headers for instance %d", instance)
	}

	// Check all three components exist for this instance
	iheader := arcHeaders[instance]
	if iheader["auth-results"] == "" || iheader["message-signature"] == "" || iheader["seal"] == "" {
		return false, "permerror", fmt.Errorf("incomplete ARC chain at instance %d", instance)
	}

	// Extract signing domain and selector from message-signature
	domain := extractTagValue(iheader["message-signature"], "d=")
	selector := extractTagValue(iheader["message-signature"], "s=")
	if domain == "" || selector == "" {
		return false, "permerror", fmt.Errorf("missing domain or selector in ARC-Message-Signature at instance %d", instance)
	}

	// Look up public key from DNS
	dkimRec, err := LookupDKIMPublicKey(selector, domain)
	if err != nil {
		return false, "temperror", fmt.Errorf("DKIM lookup failed for %s at instance %d: %w", domain, instance, err)
	}

	// Verify ARC-Message-Signature cryptographically
	msgSigValid, msgSigErr := verifyARCMessageSignature(rawMessage, iheader["message-signature"], dkimRec)
	if !msgSigValid {
		return false, "fail", fmt.Errorf("ARC-Message-Signature verification failed at instance %d: %s", instance, msgSigErr)
	}

	// Verify ARC-Seal cryptographically
	sealValid, sealErr := verifyARCSeal(iheader["auth-results"], iheader["message-signature"], iheader["seal"], dkimRec)
	if !sealValid {
		return false, "fail", fmt.Errorf("ARC-Seal verification failed at instance %d: %s", instance, sealErr)
	}

	// If this is not the first instance, check that previous instance had cv=pass
	if instance > 1 {
		prevHeaders := arcHeaders[instance-1]
		if prevHeaders == nil {
			return false, "fail", fmt.Errorf("missing previous ARC instance %d", instance-1)
		}
		prevSealCV := extractTagValue(prevHeaders["seal"], "cv=")
		if prevSealCV != "pass" {
			return false, "fail", fmt.Errorf("previous ARC instance %d has cv=%s, expected cv=pass", instance-1, prevSealCV)
		}
	}

	// All checks passed
	return true, "pass", nil
}

// ValidateARCChain validates the entire ARC chain in a message
// Performs structure validation (works offline without DNS)
// Returns comprehensive validation result with DNS lookup info
func ValidateARCChain(rawMessage []byte) *ARCValidationResult {
	result := &ARCValidationResult{
		IsValid:      false,
		Status:       "none",
		HighestValid: 0,
		Details:      "No ARC headers found",
	}

	arcHeaders := ExtractArcHeaders(rawMessage)
	if len(arcHeaders) == 0 {
		return result
	}

	// Find highest instance
	highest := 0
	for instance := range arcHeaders {
		if instance > highest {
			highest = instance
		}
	}

	// Build details for logging
	var details strings.Builder
	details.WriteString("ARC chain structure validation:\n")

	// Validate each instance in order, starting from i=1
	validUpTo := 0
	for i := 1; i <= highest; i++ {
		if arcHeaders[i] == nil {
			// Missing instance in chain
			result.Status = "fail"
			result.Details = fmt.Sprintf("broken chain: missing instance %d (have 1-%d)", i, i-1)
			result.HighestValid = validUpTo
			return result
		}

		// Check completeness
		h := arcHeaders[i]
		hasAuthResults := h["auth-results"] != ""
		hasMsgSig := h["message-signature"] != ""
		hasSeal := h["seal"] != ""

		if !hasMsgSig || !hasSeal {
			result.Status = "fail"
			result.Details = fmt.Sprintf("incomplete headers at instance %d (auth-results=%v, msg-sig=%v, seal=%v)",
				i, hasAuthResults, hasMsgSig, hasSeal)
			result.HighestValid = validUpTo
			return result
		}

		// Validate cv= value
		sealCV := extractTagValue(h["seal"], "cv=")
		if i == 1 {
			// First hop must have cv=none
			if sealCV != "none" {
				result.Status = "fail"
				result.Details = fmt.Sprintf("invalid cv value: i=1 must have cv=none, got cv=%s", sealCV)
				return result
			}
		} else {
			// Subsequent hops must have cv=pass
			if sealCV != "pass" {
				result.Status = "fail"
				result.Details = fmt.Sprintf("invalid cv value: i=%d must have cv=pass, got cv=%s", i, sealCV)
				result.HighestValid = validUpTo
				return result
			}
		}

		// Extract domain and selector for DNS lookup info
		domain := extractTagValue(h["message-signature"], "d=")
		selector := extractTagValue(h["message-signature"], "s=")
		algo := extractTagValue(h["message-signature"], "a=")

		details.WriteString(fmt.Sprintf("  ✓ i=%d: %s (cv=%s, domain=%s, selector=%s, algo=%s)\n",
			i, 
			func() string {
				if hasAuthResults && hasMsgSig && hasSeal {
					return "complete"
				}
				return "partial"
			}(),
			sealCV, domain, selector, algo))

		validUpTo = i
	}

	// All structure checks passed
	result.IsValid = true
	result.Status = "pass"
	result.HighestValid = validUpTo
	result.Details = fmt.Sprintf("ARC chain structurally valid through instance %d\n%s", 
		highest, details.String())

	return result
}

// NextArcInstance calculates what instance number to use for forwarding
// If message has existing ARC chain (i=1), returns 2
// If no ARC, returns 1
func NextArcInstance(rawMessage []byte) int {
	highest := GetHighestArcInstance(rawMessage)
	if highest == 0 {
		return 1 // No existing ARC, start fresh
	}
	return highest + 1 // Forward: add i+1
}
