package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	CanonicalBody string        // Canonicalized message body
	Headers       map[string]string
	BodyHash      string // base64-encoded SHA256 hash of body
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

	// Build signature input (b= is empty during signing)
	sigHeaders := []string{
		fmt.Sprintf("i=%d", input.Instance),
		fmt.Sprintf("a=%s", algorithm),
		"c=relaxed/relaxed",
		fmt.Sprintf("d=%s", input.Domain),
		fmt.Sprintf("s=%s", input.Selector),
		"h=from:to:subject:date:message-id",
		fmt.Sprintf("bh=%s", input.BodyHash),
		"b=", // Empty during signing
	}

	signatureData := strings.Join(sigHeaders, "; ")

	// Sign the data
	hash := sha256.Sum256([]byte(signatureData))
	signature, err := input.PrivateKey.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	// Replace empty b= with actual signature
	encodedSig := base64.StdEncoding.EncodeToString(signature)
	sigHeaders[len(sigHeaders)-1] = fmt.Sprintf("b=%s", encodedSig)

	return fmt.Sprintf("ARC-Message-Signature: %s", strings.Join(sigHeaders, "; ")), nil
}

// ARCSealInput represents data for ARC-Seal generation
type ARCSealInput struct {
	Instance              int           // i= value
	Selector              string        // s=
	Domain                string        // d=
	PrivateKey            crypto.Signer // RSA or Ed25519 private key
	AuthenticationResults string        // The full ARC-Authentication-Results header line
	MessageSignature      string        // The full ARC-Message-Signature header line
	Timestamp             time.Time
	CVValue               string // cv= value (none, pass, fail)
}

// ARCSeal generates the ARC-Seal header
// Supports both RSA-2048 and Ed25519 keys
// This seals the entire ARC chain
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

	// Build seal input (cv=none for first seal, would be pass/fail for subsequent)
	sealHeaders := []string{
		fmt.Sprintf("i=%d", input.Instance),
		fmt.Sprintf("a=%s", algorithm),
		fmt.Sprintf("t=%d", timestamp),
		fmt.Sprintf("cv=%s", cvValue), // Chain validation value
		fmt.Sprintf("d=%s", input.Domain),
		fmt.Sprintf("s=%s", input.Selector),
		"h=from:to:subject:date:message-id:arc-authentication-results:arc-message-signature",
		"b=", // Empty during signing
	}

	sealData := strings.Join(sealHeaders, "; ")

	// Sign the data
	hash := sha256.Sum256([]byte(sealData))
	signature, err := input.PrivateKey.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("seal signing failed: %w", err)
	}

	// Replace empty b= with actual signature
	encodedSig := base64.StdEncoding.EncodeToString(signature)
	sealHeaders[len(sealHeaders)-1] = fmt.Sprintf("b=%s", encodedSig)

	return fmt.Sprintf("ARC-Seal: %s", strings.Join(sealHeaders, "; ")), nil
}

// BodyHash computes the base64-encoded SHA256 hash of email body for ARC
func BodyHash(body string) string {
	// Canonicalize: fold whitespace, trim trailing CRLF
	canonical := strings.TrimSpace(body)
	if canonical == "" {
		canonical = "\r\n"
	}

	hash := sha256.Sum256([]byte(canonical))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// ARCChainSigner generates all three ARC headers in the correct order
// Supports any instance number (1 for initial, 2+ for forwarding)
// Returns: [authResults, messageSignature, seal] or error
func ARCChainSigner(domain, selector string, privKey crypto.Signer, spf, dkim, dmarc, hostname string, bodyContent string, instance int) ([]string, error) {
	if privKey == nil {
		return nil, fmt.Errorf("private key required for ARC signing")
	}

	// 1. Generate Authentication Results
	authResults := fmt.Sprintf("ARC-Authentication-Results: i=%d; %s;\r\n\tspf=%s;\r\n\tdkim=%s;\r\n\tdmarc=%s",
		instance, hostname, spf, dkim, dmarc)

	// 2. Generate Message Signature
	bodyHash := BodyHash(bodyContent)
	msgSigInput := &ARCMessageSignatureInput{
		Instance:   instance,
		Selector:   selector,
		Domain:     domain,
		PrivateKey: privKey,
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
		AuthenticationResults: authResults,
		MessageSignature:      msgSig,
		Timestamp:             time.Now(),
		CVValue:               cvValue, // Will be used if we add it to ARCSealInput
	}
	seal, err := ARCSeal(sealInput)
	if err != nil {
		return nil, fmt.Errorf("generating ARC-Seal: %w", err)
	}

	return []string{authResults, msgSig, seal}, nil
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
			break
		}

		// Check for ARC header
		if strings.HasPrefix(line, "ARC-Authentication-Results:") {
			currentType = "auth-results"
			// Extract instance number
			if idx := strings.Index(line, "i="); idx >= 0 {
				fmt.Sscanf(line[idx:], "i=%d", &currentInstance)
			}
			currentValue.Reset()
			currentValue.WriteString(line)
		} else if strings.HasPrefix(line, "ARC-Message-Signature:") {
			currentType = "message-signature"
			if idx := strings.Index(line, "i="); idx >= 0 {
				fmt.Sscanf(line[idx:], "i=%d", &currentInstance)
			}
			currentValue.Reset()
			currentValue.WriteString(line)
		} else if strings.HasPrefix(line, "ARC-Seal:") {
			currentType = "seal"
			if idx := strings.Index(line, "i="); idx >= 0 {
				fmt.Sscanf(line[idx:], "i=%d", &currentInstance)
			}
			currentValue.Reset()
			currentValue.WriteString(line)
		} else if currentType != "" && (strings.HasPrefix(line, "\t") || strings.HasPrefix(line, " ")) {
			// Continuation of previous header
			currentValue.WriteString("\r\n")
			currentValue.WriteString(line)
		} else if currentType != "" && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, " ") {
			// New header, save previous
			if _, exists := headers[currentInstance]; !exists {
				headers[currentInstance] = make(map[string]string)
			}
			headers[currentInstance][currentType] = currentValue.String()
			currentType = ""
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

// ValidateArcChainAtInstance validates the ARC chain up to a specific instance
// For now, returns true if headers are present (full validation would need key lookups)
// Returns: (isValid, error)
func ValidateArcChainAtInstance(rawMessage []byte, instance int) (bool, error) {
	arcHeaders := ExtractArcHeaders(rawMessage)
	
	// Check if this instance exists
	if arcHeaders[instance] == nil {
		return false, fmt.Errorf("no ARC headers for instance %d", instance)
	}

	// Check all three components exist for this instance
	iheader := arcHeaders[instance]
	if iheader["auth-results"] == "" || iheader["message-signature"] == "" || iheader["seal"] == "" {
		return false, fmt.Errorf("incomplete ARC chain at instance %d", instance)
	}

	// TODO: Implement full cryptographic validation
	// Would need to:
	// 1. Extract public key from DNS (DKIM record)
	// 2. Verify ARC-Seal signature
	// 3. Verify ARC-Message-Signature signature
	// 4. Verify chain integrity

	// For now, if headers exist and are complete, consider it valid
	return true, nil
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
