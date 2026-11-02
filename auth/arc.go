package auth

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ed25519"

	"gomail/logging"
)

var lookupARCKey = LookupDKIMPublicKey

// ARCAuthenticationResults builds the ARC-Authentication-Results header
// Records SPF, DKIM, and DMARC results at this hop
func ARCAuthenticationResults(hostname string, spfResult, dkimResult, dmarcResult string) string {
	return fmt.Sprintf("ARC-Authentication-Results: i=1; %s;\r\n\tspf=%s;\r\n\tdkim=%s;\r\n\tdmarc=%s",
		hostname, spfResult, dkimResult, dmarcResult)
}

// ARCMessageSignatureInput represents data for ARC-Message-Signature generation
type ARCMessageSignatureInput struct {
	Instance   int           // i= value (typically 1 for first hop)
	Selector   string        // s= (selector)
	Domain     string        // d= (domain)
	PrivateKey crypto.Signer // RSA or Ed25519 private key
	Message    []byte        // Full message (headers + body) for header extraction
	BodyHash   string        // base64-encoded SHA256 hash of body
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
	if input == nil || input.PrivateKey == nil {
		return "", fmt.Errorf("private key required")
	}
	if input.Instance < 1 || input.Instance > 50 {
		return "", fmt.Errorf("ARC instance must be between 1 and 50")
	}

	algorithm := getAlgorithm(input.PrivateKey)

	// Parse headers from message to find actual headers to include
	allHeaders, _, err := parseMessageHeaders(input.Message)
	if err != nil {
		return "", fmt.Errorf("parsing message for ARC signature: %w", err)
	}
	hasFrom := false
	for _, header := range allHeaders {
		if strings.EqualFold(header.key, "from") {
			hasFrom = true
			break
		}
	}
	if !hasFrom {
		return "", fmt.Errorf("ARC-Message-Signature requires a From header")
	}

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
	signature, err := signARCHeaderHash(input.PrivateKey, hash[:])
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
	PriorSets             map[int]map[string]string
}

// ARCSeal generates the ARC-Seal header per RFC 8617 Section 5.1.1.
// The ARC-Seal does NOT sign regular message headers.
// It only covers the ARC header set: ARC-Authentication-Results,
// ARC-Message-Signature, and the ARC-Seal itself (with b= empty).
// The ARC-Seal does NOT have an h= tag.
func ARCSeal(input *ARCSealInput) (string, error) {
	if input == nil || input.PrivateKey == nil {
		return "", fmt.Errorf("private key required")
	}
	if input.Instance < 1 || input.Instance > 50 {
		return "", fmt.Errorf("ARC instance must be between 1 and 50")
	}
	if err := validateARCHeaderTags(input.AuthenticationResults, "auth-results", input.Instance); err != nil {
		return "", err
	}
	if err := validateARCHeaderTags(input.MessageSignature, "message-signature", input.Instance); err != nil {
		return "", err
	}

	timestamp := input.Timestamp.Unix()
	if timestamp < 0 {
		return "", fmt.Errorf("ARC-Seal timestamp cannot be negative")
	}
	algorithm := getAlgorithm(input.PrivateKey)

	// Default cv value if not set
	cvValue := input.CVValue
	if cvValue == "" {
		if input.Instance != 1 {
			return "", fmt.Errorf("ARC-Seal cv= is required after instance 1")
		}
		cvValue = "none"
	}
	if input.Instance == 1 && !strings.EqualFold(cvValue, "none") ||
		input.Instance > 1 && !strings.EqualFold(cvValue, "pass") && !strings.EqualFold(cvValue, "fail") {
		return "", fmt.Errorf("invalid ARC-Seal cv=%q for instance %d", cvValue, input.Instance)
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

	sealHeader := "ARC-Seal: " + strings.Join(sealTags, "; ")
	current := map[string]string{"auth-results": input.AuthenticationResults, "message-signature": input.MessageSignature, "seal": sealHeader}
	dataToSign, err := arcSealSigningData(input.PriorSets, current, input.Instance, cvValue)
	if err != nil {
		return "", err
	}

	// Sign the data
	hash := sha256.Sum256(dataToSign)
	signature, err := signARCHeaderHash(input.PrivateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("seal signing failed: %w", err)
	}

	// Replace empty b= with actual signature
	encodedSig := base64.StdEncoding.EncodeToString(signature)
	sealTags[len(sealTags)-1] = fmt.Sprintf("b=%s", encodedSig)

	return fmt.Sprintf("ARC-Seal: %s", strings.Join(sealTags, "; ")), nil
}

func arcSealSigningData(prior map[int]map[string]string, current map[string]string, instance int, cv string) ([]byte, error) {
	if instance < 1 || instance > 50 {
		return nil, fmt.Errorf("ARC instance must be between 1 and 50")
	}
	sets := make(map[int]map[string]string, len(prior)+1)
	if !strings.EqualFold(cv, "fail") {
		for i := 1; i < instance; i++ {
			set := prior[i]
			if set == nil {
				return nil, fmt.Errorf("missing prior ARC instance %d", i)
			}
			sets[i] = set
		}
	}
	sets[instance] = current
	start := 1
	if strings.EqualFold(cv, "fail") {
		start = instance
	}
	var data bytes.Buffer
	for i := start; i <= instance; i++ {
		set := sets[i]
		for _, name := range []string{"auth-results", "message-signature", "seal"} {
			value := set[name]
			if value == "" {
				return nil, fmt.Errorf("incomplete ARC instance %d: missing %s", i, name)
			}
			if name == "seal" && i == instance {
				value = stripDKIMBValue(value)
			}
			canonical, err := relaxedCanonicalHeader(value)
			if err != nil {
				return nil, err
			}
			if data.Len() > 0 {
				data.WriteString("\r\n")
			}
			data.WriteString(canonical)
		}
	}
	return data.Bytes(), nil
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

func signARCHeaderHash(key crypto.Signer, digest []byte) ([]byte, error) {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return ed25519.Sign(k, digest), nil
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest)
	default:
		return nil, fmt.Errorf("unsupported ARC key type %T", key)
	}
}

// ARCChainSigner generates all three ARC headers in the correct order
// Supports any instance number (1 for initial, 2+ for forwarding)
// Returns: [authResults, messageSignature, seal] or error
func ARCChainSigner(domain, selector string, privKey crypto.Signer, spf, dkim, dmarc, hostname string, bodyContent string, instance int) ([]string, error) {
	if privKey == nil {
		logging.Error(fmt.Sprintf("[auth] ARC signing failed: no private key for %s/%s instance=%d", domain, selector, instance))
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
			logging.Error(fmt.Sprintf("[auth] ARC: malformed message - no header/body boundary"))
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

	cvValue := "none"
	if instance > 1 {
		if instance != NextArcInstance(msgBytes) {
			return nil, fmt.Errorf("ARC instance %d does not continue the existing chain", instance)
		}
		prior := ExtractArcHeaders(msgBytes)[instance-1]
		if strings.EqualFold(extractTagValue(prior["seal"], "cv="), "fail") {
			return nil, fmt.Errorf("cannot continue ARC chain after cv=fail at instance %d", instance-1)
		}
		validation := ValidateARCChain(msgBytes)
		switch validation.Status {
		case "pass":
			cvValue = "pass"
		case "fail", "permerror":
			cvValue = "fail"
		default:
			return nil, fmt.Errorf("cannot seal ARC chain with validation status %s: %s", validation.Status, validation.Details)
		}
	} else if GetHighestArcInstance(msgBytes) != 0 {
		return nil, fmt.Errorf("ARC instance 1 cannot replace an existing chain")
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
		PriorSets:             ExtractArcHeaders(msgBytes),
	}
	seal, err := ARCSeal(sealInput)
	if err != nil {
		logging.Error(fmt.Sprintf("[auth] ARC seal generation failed for %s/%s instance=%d: %v", domain, selector, instance, err))
		return nil, fmt.Errorf("generating ARC-Seal: %w", err)
	}

	logging.Debug(fmt.Sprintf("[auth] ARC chain signed successfully for %s/%s instance=%d", domain, selector, instance))
	return []string{authResultsHeader, msgSig, seal}, nil
}

// ExtractArcHeaders pulls all ARC headers from raw message
// Returns map of instance -> {authResults, msgSig, seal}
func ExtractArcHeaders(rawMessage []byte) map[int]map[string]string {
	headers := make(map[int]map[string]string)
	lines := strings.Split(string(rawMessage), "\r\n")
	var field strings.Builder
	flush := func() {
		if field.Len() == 0 {
			return
		}
		header := field.String()
		colon := strings.IndexByte(header, ':')
		if colon < 0 {
			return
		}
		var kind string
		switch strings.ToLower(header[:colon]) {
		case "arc-authentication-results":
			kind = "auth-results"
		case "arc-message-signature":
			kind = "message-signature"
		case "arc-seal":
			kind = "seal"
		default:
			return
		}
		unfolded := strings.ReplaceAll(header[colon+1:], "\r\n", " ")
		match := arcInstanceTag.FindStringSubmatch(unfolded)
		instance := 51 // Malformed or oversized instances must fail validation.
		if len(match) == 2 {
			if number, err := strconv.Atoi(match[1]); err == nil && number >= 1 && number <= 50 {
				instance = number
			}
		}
		if headers[instance] == nil {
			headers[instance] = make(map[string]string)
		}
		if headers[instance][kind] != "" {
			headers[instance]["duplicate-"+kind] = "true"
		}
		headers[instance][kind] = header
	}
	for _, line := range lines {
		if line == "" {
			flush()
			field.Reset()
			break
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if field.Len() > 0 {
				field.WriteString("\r\n")
				field.WriteString(line)
			}
			continue
		}
		flush()
		field.Reset()
		field.WriteString(line)
	}
	flush()
	return headers
}

var arcInstanceTag = regexp.MustCompile(`(?i)(?:^|;)\s*i\s*=\s*([0-9]+)(?:\s|;|$)`)

func validateARCHeaderTags(header, kind string, expected int) error {
	colon := strings.IndexByte(header, ':')
	if colon < 0 {
		return fmt.Errorf("malformed ARC %s header", kind)
	}
	value := strings.ReplaceAll(header[colon+1:], "\r\n", " ")
	parts := strings.Split(value, ";")
	if len(parts) < 2 {
		return fmt.Errorf("ARC %s lacks instance and payload", kind)
	}
	key, number, ok := strings.Cut(strings.TrimSpace(parts[0]), "=")
	if !ok || !strings.EqualFold(strings.TrimSpace(key), "i") || strings.TrimSpace(number) != strconv.Itoa(expected) {
		return fmt.Errorf("ARC %s must begin with i=%d", kind, expected)
	}
	if kind == "auth-results" {
		// The payload follows Authentication-Results syntax, not DKIM tags.
		// It must at least contain an authserv-id and a result (or "none").
		if len(parts) < 3 || strings.TrimSpace(parts[1]) == "" || strings.TrimSpace(parts[2]) == "" {
			return fmt.Errorf("ARC-Authentication-Results is missing authserv-id or result")
		}
		return nil
	}
	seen := map[string]bool{"i": true}
	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, _, ok := strings.Cut(part, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if !ok || name == "" || seen[name] {
			return fmt.Errorf("ARC %s has malformed or duplicate %s tag", kind, name)
		}
		seen[name] = true
		if kind == "seal" {
			switch name {
			case "a", "b", "d", "s", "t", "cv":
			default:
				return fmt.Errorf("ARC-Seal has forbidden %s tag", name)
			}
		}
	}
	return nil
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
	tags := parseDKIMTags(arcMsgSig[strings.IndexByte(arcMsgSig, ':')+1:])

	algo := tags["a"]
	headersToVerify := tags["h"]
	bodyHashB64 := tags["bh"]
	sigB64 := tags["b"]
	canonMethod := tags["c"]
	if algo != "rsa-sha256" && algo != "ed25519-sha256" {
		return false, "unsupported ARC-Message-Signature algorithm"
	}
	fromSigned := false
	for _, name := range strings.Split(headersToVerify, ":") {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "from":
			fromSigned = true
		case "authentication-results", "arc-authentication-results", "arc-message-signature", "arc-seal":
			return false, "ARC-Message-Signature h= includes an authentication-results or ARC header field"
		}
	}
	if !fromSigned {
		return false, "ARC-Message-Signature h= must include From"
	}

	if sigB64 == "" {
		return false, "missing b= in ARC-Message-Signature"
	}

	// AMS inherits DKIM's simple/simple default when c= is absent. A single
	// c= algorithm sets header canonicalization; body still defaults to simple.
	headerSimple := true
	bodySimple := true
	if canonMethod != "" {
		parts := strings.Split(canonMethod, "/")
		if len(parts) < 1 || len(parts) > 2 {
			return false, "invalid ARC-Message-Signature c= canonicalization"
		}
		switch strings.ToLower(strings.TrimSpace(parts[0])) {
		case "simple":
			headerSimple = true
		case "relaxed":
			headerSimple = false
		default:
			return false, "unsupported ARC-Message-Signature header canonicalization"
		}
		if len(parts) == 2 {
			switch strings.ToLower(strings.TrimSpace(parts[1])) {
			case "simple":
				bodySimple = true
			case "relaxed":
				bodySimple = false
			default:
				return false, "unsupported ARC-Message-Signature body canonicalization"
			}
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
	if len(revHdrs["from"]) == 0 {
		return false, "ARC-Message-Signature message has no From header"
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
	sigVal := arcMsgSigStripped
	if !strings.HasPrefix(strings.ToLower(sigVal), "arc-message-signature:") {
		sigVal = "ARC-Message-Signature: " + sigVal
	}
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
	switch algo {
	case "ed25519-sha256":
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

	case "rsa-sha256":
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

// verifyARCSeal verifies the ARC-Seal header signature. A passing chain seal
// covers every ARC set through this instance; cv=fail covers only this set.
// Returns: (isValid, errorDetail)
func verifyARCSeal(arcHeaders map[int]map[string]string, instance int, pubKeyRecord *DKIMRecord) (bool, string) {
	current := arcHeaders[instance]
	arcSeal := current["seal"]
	if arcSeal == "" {
		return false, "empty seal"
	}

	// Parse ARC-Seal tags
	tags := parseDKIMTags(arcSeal[strings.IndexByte(arcSeal, ':')+1:])

	algo := tags["a"]
	if algo != "rsa-sha256" && algo != "ed25519-sha256" {
		return false, "unsupported ARC-Seal algorithm"
	}
	sigB64 := tags["b"]
	if sigB64 == "" {
		return false, "missing b= in ARC-Seal"
	}
	if tags["c"] != "" || tags["h"] != "" {
		return false, "ARC-Seal contains a forbidden c= or h= tag"
	}
	cv := strings.ToLower(tags["cv"])
	dataToSign, dataErr := arcSealSigningData(arcHeaders, current, instance, cv)
	if dataErr != nil {
		return false, dataErr.Error()
	}

	// Verify signature
	hash := sha256.Sum256(dataToSign)
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
	switch algo {
	case "ed25519-sha256":
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

	case "rsa-sha256":
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
	dkimRec, err := lookupARCKey(selector, domain)
	if err != nil {
		if errors.Is(err, ErrDKIMInvalidRecord) {
			return false, "fail", fmt.Errorf("invalid ARC-Message-Signature key at instance %d: %w", instance, err)
		}
		return false, "temperror", fmt.Errorf("DKIM lookup failed for %s at instance %d: %w", domain, instance, err)
	}

	// Verify ARC-Message-Signature cryptographically
	msgSigValid, msgSigErr := verifyARCMessageSignature(rawMessage, iheader["message-signature"], dkimRec)
	if !msgSigValid {
		return false, "fail", fmt.Errorf("ARC-Message-Signature verification failed at instance %d: %s", instance, msgSigErr)
	}

	return validateARCSealAtInstance(arcHeaders, instance)
}

func validateARCSealAtInstance(arcHeaders map[int]map[string]string, instance int) (bool, string, error) {
	iheader := arcHeaders[instance]
	// Verify ARC-Seal cryptographically
	sealDomain := extractTagValue(iheader["seal"], "d=")
	sealSelector := extractTagValue(iheader["seal"], "s=")
	if sealDomain == "" || sealSelector == "" {
		return false, "permerror", fmt.Errorf("missing domain or selector in ARC-Seal at instance %d", instance)
	}
	sealKey, err := lookupARCKey(sealSelector, sealDomain)
	if err != nil {
		if errors.Is(err, ErrDKIMInvalidRecord) {
			return false, "fail", fmt.Errorf("invalid ARC-Seal key at instance %d: %w", instance, err)
		}
		return false, "temperror", fmt.Errorf("ARC-Seal key lookup failed for %s at instance %d: %w", sealDomain, instance, err)
	}
	sealValid, sealErr := verifyARCSeal(arcHeaders, instance, sealKey)
	if !sealValid {
		return false, "fail", fmt.Errorf("ARC-Seal verification failed at instance %d: %s", instance, sealErr)
	}

	sealCV := strings.ToLower(extractTagValue(iheader["seal"], "cv="))
	if instance == 1 && sealCV != "none" {
		return false, "fail", fmt.Errorf("ARC-Seal i=1 must use cv=none")
	}
	if instance > 1 && sealCV != "pass" {
		return false, "fail", fmt.Errorf("ARC-Seal i=%d reports cv=%s", instance, sealCV)
	}

	// All checks passed
	return true, "pass", nil
}

// ValidateARCChain validates the complete ARC structure, the newest AMS, and
// every ARC-Seal. Historical AMS signatures may legitimately fail after an
// intermediary modifies a message; RFC 8617 makes their validation optional.
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
	if len(arcHeaders) > 50 {
		result.Status = "fail"
		result.Details = "ARC chain exceeds the 50-instance limit"
		return result
	}

	// Find highest instance
	highest := 0
	for instance := range arcHeaders {
		if instance > highest {
			highest = instance
		}
	}
	if highest > 50 {
		result.Status = "fail"
		result.Details = "ARC instance exceeds 50"
		return result
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
		if h["duplicate-auth-results"] != "" || h["duplicate-message-signature"] != "" || h["duplicate-seal"] != "" {
			result.Status = "fail"
			result.Details = fmt.Sprintf("duplicate ARC header at instance %d", i)
			result.HighestValid = validUpTo
			return result
		}
		hasAuthResults := h["auth-results"] != ""
		hasMsgSig := h["message-signature"] != ""
		hasSeal := h["seal"] != ""

		if !hasAuthResults || !hasMsgSig || !hasSeal {
			result.Status = "fail"
			result.Details = fmt.Sprintf("incomplete headers at instance %d (auth-results=%v, msg-sig=%v, seal=%v)",
				i, hasAuthResults, hasMsgSig, hasSeal)
			result.HighestValid = validUpTo
			return result
		}
		for _, kind := range []string{"auth-results", "message-signature", "seal"} {
			if err := validateARCHeaderTags(h[kind], kind, i); err != nil {
				result.Status = "fail"
				result.Details = err.Error()
				result.HighestValid = validUpTo
				return result
			}
		}

		// Validate cv= value
		sealCV := strings.ToLower(extractTagValue(h["seal"], "cv="))
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

	// The newest AMS must verify against the current message. Earlier AMS
	// signatures need not: later intermediaries may have changed the content.
	valid, status, err := ValidateArcChainAtInstance(rawMessage, highest)
	if !valid {
		result.Status = status
		result.Details = err.Error()
		result.HighestValid = highest - 1
		return result
	}
	// Validate every older seal, even when its AMS no longer verifies.
	for i := highest - 1; i >= 1; i-- {
		valid, status, err := validateARCSealAtInstance(arcHeaders, i)
		if !valid {
			result.Status = status
			result.Details = err.Error()
			result.HighestValid = 0
			return result
		}
	}

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
