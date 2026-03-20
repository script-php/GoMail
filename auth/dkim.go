package auth

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// DKIMSigner handles outbound DKIM signing.
type DKIMSigner struct {
	Domain     string
	Selector   string
	PrivateKey crypto.Signer
	Algorithm  string // "ed25519" or "rsa"
}

// NewDKIMSigner loads the private key from a file and creates a signer.
func NewDKIMSigner(domain, selector, keyPath, algorithm string) (*DKIMSigner, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading DKIM key: %w", err)
	}
	return NewDKIMSignerFromPEM(domain, selector, keyData, algorithm)
}

// NewDKIMSignerFromPEM creates a signer from PEM-encoded private key data.
// This is used for per-domain DKIM keys stored in the database.
func NewDKIMSignerFromPEM(domain, selector string, pemData []byte, algorithm string) (*DKIMSigner, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in DKIM key")
	}

	var signer crypto.Signer

	switch algorithm {
	case "ed25519":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing ed25519 private key: %w", err)
		}
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not ed25519")
		}
		signer = edKey
	case "rsa":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS1 as fallback
			key2, err2 := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err2 != nil {
				return nil, fmt.Errorf("parsing RSA key: %w (PKCS8: %v)", err2, err)
			}
			signer = key2
		} else {
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("key is not RSA")
			}
			signer = rsaKey
		}
	default:
		return nil, fmt.Errorf("unsupported DKIM algorithm: %s", algorithm)
	}

	return &DKIMSigner{
		Domain:     domain,
		Selector:   selector,
		PrivateKey: signer,
		Algorithm:  algorithm,
	}, nil
}

// GenerateDKIMKeyPair generates a DKIM key pair and returns PEM-encoded strings.
// Returns: privateKeyPEM, publicKeyPEM, dnsRecordValue, error
func GenerateDKIMKeyPair(algorithm string) (string, string, string, error) {
	switch algorithm {
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", "", "", fmt.Errorf("generating ed25519 key: %w", err)
		}
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return "", "", "", fmt.Errorf("marshaling private key: %w", err)
		}
		privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}))

		pubBytes, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return "", "", "", fmt.Errorf("marshaling public key: %w", err)
		}
		pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))
		pubB64 := base64.StdEncoding.EncodeToString(pubBytes)
		dnsRecord := fmt.Sprintf("v=DKIM1; k=ed25519; p=%s", pubB64)
		return privPEM, pubPEM, dnsRecord, nil

	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", "", "", fmt.Errorf("generating RSA key: %w", err)
		}
		privBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return "", "", "", fmt.Errorf("marshaling RSA private key: %w", err)
		}
		privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}))

		pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return "", "", "", fmt.Errorf("marshaling RSA public key: %w", err)
		}
		pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))
		pubB64 := base64.StdEncoding.EncodeToString(pubBytes)
		dnsRecord := fmt.Sprintf("v=DKIM1; k=rsa; p=%s", pubB64)
		return privPEM, pubPEM, dnsRecord, nil

	default:
		return "", "", "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// Sign adds a DKIM-Signature header to the message and returns the signed message.
func (s *DKIMSigner) Sign(message []byte) ([]byte, error) {
	// Split headers and body
	headerEnd := bytes.Index(message, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		headerEnd = bytes.Index(message, []byte("\n\n"))
		if headerEnd == -1 {
			return nil, fmt.Errorf("cannot find end of headers")
		}
	}

	headers := string(message[:headerEnd])
	body := message[headerEnd:]

	// Canonicalize body (simple: ensure trailing CRLF)
	bodyCanon := canonicalizeBodySimple(body)

	// Body hash
	bodyHash := sha256.Sum256(bodyCanon)
	bh := base64.StdEncoding.EncodeToString(bodyHash[:])

	// Headers to sign
	signHeaders := []string{"from", "to", "subject", "date", "message-id"}
	var signedHeaderNames []string

	headerLines := parseHeaderLines(headers)
	for _, sh := range signHeaders {
		for _, hl := range headerLines {
			if strings.EqualFold(hl.key, sh) {
				signedHeaderNames = append(signedHeaderNames, sh)
				break
			}
		}
	}

	// Build DKIM-Signature header (without b= value)
	algo := "ed25519-sha256"
	if s.Algorithm == "rsa" {
		algo = "rsa-sha256"
	}

	timestamp := time.Now().Unix()
	expiration := timestamp + 7*86400 // 7 days

	dkimHeader := fmt.Sprintf(
		"DKIM-Signature: v=1; a=%s; c=relaxed/simple; d=%s; s=%s; t=%d; x=%d; h=%s; bh=%s; b=",
		algo, s.Domain, s.Selector, timestamp, expiration,
		strings.Join(signedHeaderNames, ":"), bh,
	)

	// Build canonical header data for signing
	var dataToSign bytes.Buffer
	for _, sh := range signedHeaderNames {
		for _, hl := range headerLines {
			if strings.EqualFold(hl.key, sh) {
				dataToSign.WriteString(canonicalizeHeaderRelaxed(hl.raw))
				dataToSign.WriteString("\r\n")
				break
			}
		}
	}
	// Add DKIM-Signature header itself (without b= value, no trailing CRLF)
	dataToSign.WriteString(canonicalizeHeaderRelaxed(dkimHeader))

	// Sign
	hash := sha256.Sum256(dataToSign.Bytes())

	var sig []byte
	switch key := s.PrivateKey.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(key, hash[:])
	case *rsa.PrivateKey:
		var err error
		sig, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		if err != nil {
			return nil, fmt.Errorf("RSA signing: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	sigB64 := base64.StdEncoding.EncodeToString(sig)
	fullDKIMHeader := dkimHeader + sigB64

	// Prepend DKIM-Signature to message
	var result bytes.Buffer
	result.WriteString(fullDKIMHeader)
	result.WriteString("\r\n")
	result.Write(message)

	return result.Bytes(), nil
}

// VerifyDKIM performs basic DKIM verification on an inbound message.
// Returns "pass", "fail", or "none".
func VerifyDKIM(message []byte) (string, string) {
	headerEnd := bytes.Index(message, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		headerEnd = bytes.Index(message, []byte("\n\n"))
		if headerEnd == -1 {
			return "none", "no headers found"
		}
	}

	headers := string(message[:headerEnd])
	body := message[headerEnd:]

	// Find DKIM-Signature header
	headerLines := parseHeaderLines(headers)
	var dkimSig string
	for _, hl := range headerLines {
		if strings.EqualFold(hl.key, "DKIM-Signature") {
			dkimSig = hl.value
			break
		}
	}

	if dkimSig == "" {
		return "none", "no DKIM-Signature header"
	}

	// Parse DKIM tag=value pairs
	tags := parseDKIMTags(dkimSig)

	domain := tags["d"]
	selector := tags["s"]
	algo := tags["a"]
	headersToVerify := tags["h"]
	bodyHashB64 := tags["bh"]
	sigB64 := tags["b"]

	if domain == "" || selector == "" || sigB64 == "" {
		return "fail", "missing required DKIM tags"
	}

	// Verify body hash
	bodyCanon := canonicalizeBodySimple(body)
	bodyHash := sha256.Sum256(bodyCanon)
	expectedBH := base64.StdEncoding.EncodeToString(bodyHash[:])
	if bodyHashB64 != expectedBH {
		return "fail", "body hash mismatch"
	}

	// Lookup public key
	pubKeyRecord := fmt.Sprintf("%s._domainkey.%s", selector, domain)
	txtRecords, err := net.LookupTXT(pubKeyRecord)
	if err != nil {
		return "fail", fmt.Sprintf("DNS lookup failed for %s: %v", pubKeyRecord, err)
	}

	var pubKeyB64 string
	for _, txt := range txtRecords {
		if strings.Contains(txt, "p=") {
			dkimTags := parseDKIMTags(txt)
			pubKeyB64 = dkimTags["p"]
			break
		}
	}

	if pubKeyB64 == "" {
		return "fail", "no public key in DNS"
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return "fail", "invalid public key encoding"
	}

	// Reconstruct signed data
	var dataToSign bytes.Buffer
	signHeaderNames := strings.Split(headersToVerify, ":")
	for _, sh := range signHeaderNames {
		sh = strings.TrimSpace(sh)
		for _, hl := range headerLines {
			if strings.EqualFold(hl.key, sh) {
				dataToSign.WriteString(canonicalizeHeaderRelaxed(hl.raw))
				dataToSign.WriteString("\r\n")
				break
			}
		}
	}

	// Add DKIM-Signature with empty b=
	for _, hl := range headerLines {
		if strings.EqualFold(hl.key, "DKIM-Signature") {
			stripped := stripDKIMB(hl.raw)
			dataToSign.WriteString(canonicalizeHeaderRelaxed(stripped))
			break
		}
	}

	hash := sha256.Sum256(dataToSign.Bytes())

	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return "fail", "invalid signature encoding"
	}

	// Verify based on algorithm
	switch {
	case strings.Contains(algo, "ed25519"):
		if len(pubKeyBytes) == ed25519.PublicKeySize {
			if ed25519.Verify(ed25519.PublicKey(pubKeyBytes), hash[:], sigBytes) {
				return "pass", "DKIM signature valid"
			}
		} else {
			// Try parsing as PKIX
			key, err := x509.ParsePKIXPublicKey(pubKeyBytes)
			if err != nil {
				return "fail", "cannot parse ed25519 public key"
			}
			edPub, ok := key.(ed25519.PublicKey)
			if !ok {
				return "fail", "key is not ed25519"
			}
			if ed25519.Verify(edPub, hash[:], sigBytes) {
				return "pass", "DKIM signature valid"
			}
		}
		return "fail", "DKIM signature invalid"

	case strings.Contains(algo, "rsa"):
		key, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err != nil {
			return "fail", "cannot parse RSA public key"
		}
		rsaPub, ok := key.(*rsa.PublicKey)
		if !ok {
			return "fail", "key is not RSA"
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sigBytes); err != nil {
			return "fail", "DKIM signature invalid"
		}
		return "pass", "DKIM signature valid"
	}

	return "fail", fmt.Sprintf("unsupported algorithm: %s", algo)
}

// GenerateDKIMKeys generates a new Ed25519 key pair for DKIM signing and writes to files.
// Deprecated: use GenerateDKIMKeyPair for per-domain keys stored in DB.
func GenerateDKIMKeys(keyDir string) error {
	privPEM, pubPEM, dnsRecord, err := GenerateDKIMKeyPair("ed25519")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return fmt.Errorf("creating key directory: %w", err)
	}
	if err := os.WriteFile(keyDir+"/dkim_private.pem", []byte(privPEM), 0600); err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}
	if err := os.WriteFile(keyDir+"/dkim_public.pem", []byte(pubPEM), 0644); err != nil {
		return fmt.Errorf("writing public key: %w", err)
	}
	if err := os.WriteFile(keyDir+"/dkim_dns_record.txt", []byte(dnsRecord+"\n"), 0644); err != nil {
		return fmt.Errorf("writing DNS record: %w", err)
	}

	return nil
}

// --- Helper functions ---

type headerLine struct {
	key   string
	value string
	raw   string
}

func parseHeaderLines(headers string) []headerLine {
	var lines []headerLine
	// Normalize line endings
	headers = strings.ReplaceAll(headers, "\r\n", "\n")
	rawLines := strings.Split(headers, "\n")

	var current string
	for _, line := range rawLines {
		if line == "" {
			continue
		}
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			// Continuation line
			current += "\r\n" + line
			continue
		}
		if current != "" {
			lines = append(lines, makeHeaderLine(current))
		}
		current = line
	}
	if current != "" {
		lines = append(lines, makeHeaderLine(current))
	}
	return lines
}

func makeHeaderLine(raw string) headerLine {
	idx := strings.IndexByte(raw, ':')
	if idx == -1 {
		return headerLine{raw: raw}
	}
	return headerLine{
		key:   strings.TrimSpace(raw[:idx]),
		value: strings.TrimSpace(raw[idx+1:]),
		raw:   raw,
	}
}

func canonicalizeBodySimple(body []byte) []byte {
	// Simple canonicalization: ensure body ends with single CRLF
	b := bytes.TrimRight(body, "\r\n")
	if len(b) == 0 {
		return []byte("\r\n")
	}
	return append(b, '\r', '\n')
}

func canonicalizeHeaderRelaxed(header string) string {
	idx := strings.IndexByte(header, ':')
	if idx == -1 {
		return header
	}
	key := strings.ToLower(strings.TrimSpace(header[:idx]))
	value := header[idx+1:]
	// Unfold and compress whitespace
	value = strings.ReplaceAll(value, "\r\n", "")
	value = strings.ReplaceAll(value, "\n", "")
	value = strings.Join(strings.Fields(value), " ")
	value = strings.TrimSpace(value)
	return key + ":" + value
}

func parseDKIMTags(s string) map[string]string {
	tags := make(map[string]string)
	// Remove whitespace from the value
	s = strings.ReplaceAll(s, "\r\n", "")
	s = strings.ReplaceAll(s, "\n", "")
	parts := strings.Split(s, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		idx := strings.IndexByte(part, '=')
		if idx == -1 {
			continue
		}
		key := strings.TrimSpace(part[:idx])
		value := strings.TrimSpace(part[idx+1:])
		// Remove whitespace from value (e.g., multiline base64)
		value = strings.Join(strings.Fields(value), "")
		tags[key] = value
	}
	return tags
}

func stripDKIMB(header string) string {
	// Remove the b= value from DKIM-Signature for verification
	idx := strings.Index(header, "b=")
	if idx == -1 {
		return header
	}
	// Find the end of b= value (next ; or end of string)
	rest := header[idx+2:]
	semiIdx := strings.IndexByte(rest, ';')
	if semiIdx == -1 {
		return header[:idx+2]
	}
	return header[:idx+2] + rest[semiIdx:]
}

// Ensure sorted unused
var _ = sort.Strings
