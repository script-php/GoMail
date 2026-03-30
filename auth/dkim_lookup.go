package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/ed25519"
)

// DKIMRecord represents a parsed DKIM record from DNS
type DKIMRecord struct {
	Version   string // v= (default DKIM1)
	Algorithm string // a= (rsa-sha256, ed25519-sha256)
	HashAlgo  string // h= (sha256, sha1)
	PublicKey crypto.PublicKey
	RawKey    string
	Flags     string // t= (flags like y, s)
	Notes     string // n=
}

// LookupDKIMPublicKey retrieves the DKIM public key from DNS
// Returns the parsed DKIM record or error if not found/invalid
func LookupDKIMPublicKey(selector, domain string) (*DKIMRecord, error) {
	// Query DNS TXT record at selector._domainkey.domain
	lookupHost := fmt.Sprintf("%s._domainkey.%s", selector, domain)

	txts, err := net.LookupTXT(lookupHost)
	if err != nil {
		dnsErr, ok := err.(*net.DNSError)
		if ok && dnsErr.IsNotFound {
			return nil, fmt.Errorf("DKIM record not found at %s", lookupHost)
		}
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", lookupHost, err)
	}

	if len(txts) == 0 {
		return nil, fmt.Errorf("no TXT records found at %s", lookupHost)
	}

	// Parse the TXT record (multiple records concatenated, use first)
	record := parseDKIMRecord(txts[0])
	if record == nil {
		return nil, fmt.Errorf("invalid DKIM record at %s", lookupHost)
	}

	return record, nil
}

// parseDKIMRecord parses a DKIM record string from DNS
func parseDKIMRecord(recordStr string) *DKIMRecord {
	record := &DKIMRecord{
		Version:  "DKIM1", // Default
		Algorithm: "rsa-sha256", // Default
		HashAlgo: "sha256",      // Default
	}

	// Parse semi-colon separated key=value pairs
	parts := strings.Split(recordStr, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		switch key {
		case "v":
			record.Version = value
		case "a":
			record.Algorithm = value
		case "h":
			record.HashAlgo = value
		case "p":
			record.RawKey = value
		case "t":
			record.Flags = value
		case "n":
			record.Notes = value
		}
	}

	// Version must be DKIM1
	if record.Version != "DKIM1" {
		return nil
	}

	// Need algorithm and public key
	if record.Algorithm == "" || record.RawKey == "" {
		return nil
	}

	// Decode public key
	keyBytes, err := base64.StdEncoding.DecodeString(record.RawKey)
	if err != nil {
		return nil
	}

	// Parse public key based on algorithm
	switch record.Algorithm {
	case "rsa-sha256":
		pub, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			return nil
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil
		}
		record.PublicKey = rsaPub

	case "ed25519-sha256":
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil
		}
		record.PublicKey = ed25519.PublicKey(keyBytes)

	default:
		return nil
	}

	return record
}

// VerifyDKIMSignature verifies a DKIM-Signature on a message
// Returns: pass (valid), fail (invalid), temperror, permerror
func VerifyDKIMSignature(dkimSig string, canonBody, canonHeaders string, record *DKIMRecord) string {
	if record == nil || record.PublicKey == nil {
		return "permerror" // No public key
	}

	// Extract b= value (signature)
	sigB64 := extractTagValue(dkimSig, "b=")
	if sigB64 == "" {
		return "permerror"
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return "permerror"
	}

	// Build canonical input
	canonInput := canonHeaders + "\r\n" + canonBody

	// Verify based on algorithm
	algo := extractTagValue(dkimSig, "a=")
	switch algo {
	case "rsa-sha256":
		rsaPub, ok := record.PublicKey.(*rsa.PublicKey)
		if !ok {
			return "permerror"
		}
		h := sha256Sum([]byte(canonInput))
		err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, h[:], sig)
		if err != nil {
			return "fail"
		}
		return "pass"

	case "ed25519-sha256":
		ed25519Pub, ok := record.PublicKey.(ed25519.PublicKey)
		if !ok {
			return "permerror"
		}
		h := sha256Sum([]byte(canonInput))
		if !ed25519.Verify(ed25519Pub, h[:], sig) {
			return "fail"
		}
		return "pass"

	default:
		return "permerror"
	}
}

// VerifyARCChainSignature verifies an ARC-Message-Signature signature
// Returns: pass, fail, permerror
func VerifyARCChainSignature(arcSig string, canonBody, canonHeaders string, record *DKIMRecord) string {
	// Similar to DKIM verification
	return VerifyDKIMSignature(arcSig, canonBody, canonHeaders, record)
}

// extractTagValue extracts a tag value from a signature header
// e.g., extractTagValue("a=rsa-sha256; b=xyz", "b=") returns "xyz"
func extractTagValue(header, tag string) string {
	// Find tag position
	idx := strings.Index(header, tag)
	if idx == -1 {
		return ""
	}

	// Move past tag
	start := idx + len(tag)
	value := header[start:]

	// Find semicolon or end of string
	endIdx := strings.Index(value, ";")
	if endIdx == -1 {
		return strings.TrimSpace(value)
	}

	return strings.TrimSpace(value[:endIdx])
}

// sha256Sum computes SHA256 hash
func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}
