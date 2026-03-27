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
)

// ARCAuthenticationResults builds the ARC-Authentication-Results header
// Records SPF, DKIM, and DMARC results at this hop
func ARCAuthenticationResults(hostname string, spfResult, dkimResult, dmarcResult string) string {
	return fmt.Sprintf("ARC-Authentication-Results: i=1; %s;\r\n\tspf=%s;\r\n\tdkim=%s;\r\n\tdmarc=%s",
		hostname, spfResult, dkimResult, dmarcResult)
}

// ARCMessageSignatureInput represents data for ARC-Message-Signature generation
type ARCMessageSignatureInput struct {
	Instance      int    // i= value (typically 1 for first hop)
	Selector      string // s= (selector)
	Domain        string // d= (domain)
	SigningKey    *rsa.PrivateKey
	CanonicalBody string // Canonicalized message body
	Headers       map[string]string
	BodyHash      string // base64-encoded SHA256 hash of body
}

// ARCMessageSignature generates the ARC-Message-Signature header
func ARCMessageSignature(input *ARCMessageSignatureInput) (string, error) {
	if input.SigningKey == nil {
		return "", fmt.Errorf("signing key required")
	}

	// Build signature input (b= is empty during signing)
	sigHeaders := []string{
		fmt.Sprintf("i=%d", input.Instance),
		"a=rsa-sha256",
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
	signature, err := rsa.SignPKCS1v15(rand.Reader, input.SigningKey, crypto.SHA256, hash[:])
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
	Instance           int    // i= value
	Selector           string // s=
	Domain             string // d=
	SigningKey         *rsa.PrivateKey
	AuthenticationResults string // The full ARC-Authentication-Results header line
	MessageSignature   string // The full ARC-Message-Signature header line
	Timestamp          time.Time
}

// ARCSeal generates the ARC-Seal header
// This seals the entire ARC chain
func ARCSeal(input *ARCSealInput) (string, error) {
	if input.SigningKey == nil {
		return "", fmt.Errorf("signing key required")
	}

	timestamp := input.Timestamp.Unix()

	// Build seal input (cv=none for first seal, would be pass/fail for subsequent)
	sealHeaders := []string{
		fmt.Sprintf("i=%d", input.Instance),
		"a=rsa-sha256",
		fmt.Sprintf("t=%d", timestamp),
		"cv=none", // No prior ARC chain
		fmt.Sprintf("d=%s", input.Domain),
		fmt.Sprintf("s=%s", input.Selector),
		"h=from:to:subject:date:message-id:arc-authentication-results:arc-message-signature",
		"b=", // Empty during signing
	}

	sealData := strings.Join(sealHeaders, "; ")

	// Sign the data
	hash := sha256.Sum256([]byte(sealData))
	signature, err := rsa.SignPKCS1v15(rand.Reader, input.SigningKey, crypto.SHA256, hash[:])
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
