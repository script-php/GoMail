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
	// Parse headers from message
	headers, bodyOffset, err := parseMessageHeaders(message)
	if err != nil {
		return nil, fmt.Errorf("parsing headers: %w", err)
	}

	// Extract body
	body := message[bodyOffset:]

	// Canonicalize body (relaxed canonicalization)
	bodyCanonBytes := bodyHashFunc(false, body) // false = not simple, so relaxed
	bh := base64.StdEncoding.EncodeToString(bodyCanonBytes)

	// Headers to sign (in order)
	signHeaders := []string{"from", "to", "subject", "date", "message-id"}
	var signedHeaderNames []string

	// Find which headers are present in the message
	for _, sh := range signHeaders {
		for _, h := range headers {
			if strings.EqualFold(h.key, sh) {
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
		"DKIM-Signature: v=1; a=%s; c=relaxed/relaxed; d=%s; s=%s; t=%d; x=%d; h=%s; bh=%s; b=",
		algo, s.Domain, s.Selector, timestamp, expiration,
		strings.Join(signedHeaderNames, ":"), bh,
	)

	// Build canonical header data for signing (like RFC 6376 specifies)
	var dataToSign bytes.Buffer
	for _, sh := range signedHeaderNames {
		for _, h := range headers {
			if strings.EqualFold(h.key, sh) {
				// Convert raw bytes to string for canonicalization
				rawStr := strings.TrimSpace(h.key) + ":" + h.value
				canonical, _ := relaxedCanonicalHeader(rawStr)
				dataToSign.WriteString(canonical)
				dataToSign.WriteString("\r\n")
				break
			}
		}
	}
	
	// Add DKIM-Signature header itself (without b= value, no trailing CRLF on last header)
	dkimCanonical, _ := relaxedCanonicalHeader(dkimHeader)
	dataToSign.WriteString(dkimCanonical)

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
// VerifyDKIM verifies a DKIM signature on an email message.
// Returns: (status, detail) where status is "pass", "fail", or "none"
func VerifyDKIM(message []byte) (string, string) {
	// Parse the message into headers and body using proper line-ending preservation
	hdrs, bodyOffset, err := parseMessageHeaders(message)
	if err != nil {
		return "none", "malformed headers"
	}

	// Find DKIM-Signature header
	var dkimSig *headerRaw
	for _, h := range hdrs {
		if strings.EqualFold(h.key, "dkim-signature") {
			dkimSig = h
			break
		}
	}

	if dkimSig == nil {
		return "none", "no DKIM-Signature header"
	}

	// Parse DKIM tags
	tags := parseDKIMTags(dkimSig.value)

	domain := tags["d"]
	selector := tags["s"]
	algo := tags["a"]
	headersToVerify := tags["h"]
	bodyHashB64 := tags["bh"]
	sigB64 := tags["b"]
	canonMethod := tags["c"]

	if domain == "" || selector == "" || sigB64 == "" {
		return "fail", "missing required DKIM tags"
	}

	// Parse canonicalization (default: simple/simple)
	headerSimple := true
	bodySimple := true
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
	body := message[bodyOffset:]
	bodyHash := bodyHashFunc(bodySimple, body)
	expectedBH := base64.StdEncoding.EncodeToString(bodyHash)
	if bodyHashB64 != expectedBH {
		return "fail", "body hash mismatch"
	}

	// Get public key from DNS
	pubKeyRecord := fmt.Sprintf("%s._domainkey.%s", selector, domain)
	txtRecords, err := net.LookupTXT(pubKeyRecord)
	if err != nil {
		return "fail", fmt.Sprintf("DNS lookup failed: %v", err)
	}

	if len(txtRecords) == 0 {
		return "fail", "no DKIM public key in DNS"
	}

	var pubKeyB64 string
	for _, txt := range txtRecords {
		dkimTags := parseDKIMTags(txt)
		if pubKeyB64 = dkimTags["p"]; pubKeyB64 != "" {
			break
		}
	}

	if pubKeyB64 == "" {
		return "fail", "no public key in DNS record"
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return "fail", "invalid public key encoding"
	}

	// Build the data to be signed. Use MOX's approach:
	// Store headers in reverse order map, then pull from them as needed.
	revHdrs := make(map[string][]*headerRaw)
	for _, h := range hdrs {
		lkey := strings.ToLower(h.key)
		// Prepend to list (reverse order)
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

		// Take first from list and remove it
		h := hdrsForKey[0]
		revHdrs[lkey] = hdrsForKey[1:]

		// Canonicalize header
		hval := string(h.raw)
		if !headerSimple {
			hval, _ = relaxedCanonicalHeader(hval)
		}

		dataToSign.WriteString(hval)
		dataToSign.WriteString("\r\n")
	}

	// Add DKIM-Signature header with b= value removed
	dkimVerifySig := stripDKIMBValue(string(dkimSig.raw))
	if !headerSimple {
		dkimVerifySig, _ = relaxedCanonicalHeader(dkimVerifySig)
	}
	dataToSign.WriteString(dkimVerifySig)

	// Verify signature
	hash := sha256.Sum256(dataToSign.Bytes())
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return "fail", "invalid signature encoding"
	}

	// Determine algorithm and verify
	switch {
	case strings.Contains(algo, "ed25519"):
		key, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err == nil {
			if edPub, ok := key.(ed25519.PublicKey); ok {
				if ed25519.Verify(edPub, hash[:], sigBytes) {
					return "pass", "DKIM signature valid"
				}
			}
		} else if len(pubKeyBytes) == ed25519.PublicKeySize {
			if ed25519.Verify(ed25519.PublicKey(pubKeyBytes), hash[:], sigBytes) {
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

type headerRaw struct {
	key   string   // Original case
	lkey  string   // Lowercase key
	value string   // Value (unfolded)
	raw   []byte   // Complete header including key, colon, and original formatting
}

// parseMessageHeaders parses headers from a message, preserving CRLF structure.
// Returns headers slice and byte offset where body starts.
func parseMessageHeaders(message []byte) ([]*headerRaw, int, error) {
	// Find header/body boundary
	headerEnd := bytes.Index(message, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		headerEnd = bytes.Index(message, []byte("\n\n"))
		if headerEnd == -1 {
			return nil, 0, fmt.Errorf("no header/body boundary found")
		}
		// For \n\n boundary, body starts after
		return parseHeadersFromBytes(message[:headerEnd]), headerEnd + 2, nil
	}

	// Parse headers with proper CRLF preservation
	hdrs := parseHeadersFromBytes(message[:headerEnd])
	return hdrs, headerEnd + 4, nil
}

func parseHeadersFromBytes(headerBytes []byte) []*headerRaw {
	var hdrs []*headerRaw
	i := 0
	
	for i < len(headerBytes) {
		// Check for empty line (end of headers)
		if i+1 <= len(headerBytes) && headerBytes[i] == '\r' && i+1 < len(headerBytes) && headerBytes[i+1] == '\n' {
			break
		}
		if headerBytes[i] == '\n' {
			break
		}
		
		// Read this complete header line (including continuations)
		lineStart := i
		lineEnd := i
		
		// Scan to end of header, including folded lines
		for i < len(headerBytes) {
			// Look for CRLF
			if i+1 < len(headerBytes) && headerBytes[i] == '\r' && headerBytes[i+1] == '\n' {
				lineEnd = i + 2
				i = lineEnd
				// Check if next line is continuation (starts with space or tab)
				if i < len(headerBytes) && (headerBytes[i] == ' ' || headerBytes[i] == '\t') {
					continue
				}
				break
			}
			// Look for LF only
			if headerBytes[i] == '\n' {
				lineEnd = i + 1
				i = lineEnd
				// Check if next line is continuation
				if i < len(headerBytes) && (headerBytes[i] == ' ' || headerBytes[i] == '\t') {
					continue
				}
				break
			}
			i++
		}
		
		// If we reached EOF without finding line ending, use rest of buffer
		if lineEnd == lineStart {
			lineEnd = len(headerBytes)
		}
		
		if lineEnd <= lineStart {
			break
		}
		
		// Extract line and trim line endings
		line := bytes.TrimRight(headerBytes[lineStart:lineEnd], "\r\n")
		
		if len(line) == 0 {
			break
		}
		
		// Find colon
		colonIdx := bytes.IndexByte(line, ':')
		if colonIdx == -1 {
			continue
		}
		
		keyPart := strings.TrimSpace(string(line[:colonIdx]))
		valuePart := strings.TrimSpace(string(line[colonIdx+1:]))
		
		hdrs = append(hdrs, &headerRaw{
			key:   keyPart,
			lkey:  strings.ToLower(keyPart),
			value: valuePart,
			raw:   line,
		})
	}
	
	return hdrs
}

// bodyHashFunc calculates body hash according to RFC 6376
// Returns []byte specifically (not [32]byte)
func bodyHashFunc(simpleCanon bool, body []byte) []byte {
	if simpleCanon {
		return bodyHashSimple(body)
	}
	return bodyHashRelaxed(body)
}

// bodyHashSimple implements simple body canonicalization (RFC 6376 section 3.7.1)
// Ensure body ends with exactly one trailing CRLF
func bodyHashSimple(body []byte) []byte {
	// Trim all CRLF/LF from end
	body = bytes.TrimRight(body, "\r\n")
	if len(body) == 0 {
		h := sha256.Sum256([]byte("\r\n"))
		return h[:]
	}
	// Add exactly one CRLF
	result := append(body, '\r', '\n')
	h := sha256.Sum256(result)
	return h[:]
}

// bodyHashRelaxed implements relaxed body canonicalization (RFC 6376 section 3.7.2)
func bodyHashRelaxed(body []byte) []byte {
	// Split into lines
	lines := bytes.Split(body, []byte("\n"))

	var processed [][]byte
	for _, line := range lines {
		// Remove trailing \r if present
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		// Remove trailing whitespace
		line = bytes.TrimRight(line, " \t")

		// Collapse internal whitespace
		if len(line) > 0 {
			line = collapseWSP(line)
		}

		processed = append(processed, line)
	}

	// Remove all trailing empty lines
	for len(processed) > 0 && len(processed[len(processed)-1]) == 0 {
		processed = processed[:len(processed)-1]
	}

	if len(processed) == 0 {
		h := sha256.Sum256([]byte("\r\n"))
		return h[:]
	}

	// Rejoin with CRLF
	result := bytes.Join(processed, []byte("\r\n"))
	result = append(result, '\r', '\n')
	h := sha256.Sum256(result)
	return h[:]
}

// collapseWSP replaces sequences of space/tab with a single space
func collapseWSP(line []byte) []byte {
	var result []byte
	prev := byte(0)
	for _, b := range line {
		if b == ' ' || b == '\t' {
			if prev != ' ' {
				result = append(result, ' ')
				prev = ' '
			}
		} else {
			result = append(result, b)
			prev = b
		}
	}
	return result
}

// relaxedCanonicalHeader returns a relaxed canonical form of a header.
// From RFC 6376 section 3.7.2:
// - Ignore all whitespace at end of lines
// - Reduce all sequences of WSP within a line to a single SP
// Returns with CRLF if present in original, without if not.
func relaxedCanonicalHeader(header string) (string, error) {
	// Split on first colon
	idx := strings.Index(header, ":")
	if idx == -1 {
		return "", fmt.Errorf("invalid header: no colon")
	}

	key := strings.ToLower(strings.TrimSpace(header[:idx]))
	value := header[idx+1:]

	// Unfold (remove line breaks)
	value = strings.ReplaceAll(value, "\r\n", "")
	value = strings.ReplaceAll(value, "\n", "")

	// Replace sequences of WSP with single space
	value = collapseWhitespace(value)

	// Trim leading and trailing whitespace from value
	value = strings.Trim(value, " \t")

	return key + ":" + value, nil
}

// collapseWhitespace replaces sequences of space/tab with single space
func collapseWhitespace(s string) string {
	var result []byte
	prev := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' {
			if prev != ' ' {
				result = append(result, ' ')
				prev = ' '
			}
		} else {
			result = append(result, c)
			prev = c
		}
	}
	return string(result)
}

// stripDKIMBValue removes the value from the "b=" field in a DKIM-Signature header.
// Returns the header with "b=" but no value.
func stripDKIMBValue(header string) string {
	// Find "b="
	bIdx := strings.Index(header, "b=")
	if bIdx == -1 {
		// No b= field, return as-is
		return header
	}

	// Find the end of the b= value (next semicolon or end of line)
	rest := header[bIdx+2:]
	semiIdx := strings.IndexByte(rest, ';')

	if semiIdx == -1 {
		// b= goes to the end, remove everything after
		return header[:bIdx+2]
	}

	// b= value ends at semicolon
	return header[:bIdx+2] + rest[semiIdx:]
}

func parseDKIMTags(s string) map[string]string {
	tags := make(map[string]string)
	// Remove all newlines and folding
	s = strings.ReplaceAll(s, "\r\n", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")

	// Split on semicolons
	parts := strings.Split(s, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		idx := strings.IndexByte(part, '=')
		if idx == -1 {
			continue
		}

		key := strings.TrimSpace(part[:idx])
		value := strings.TrimSpace(part[idx+1:])
		// For the h= tag (header list), clean up spaces around colons
		// For other values, remove internal whitespace completely
		if strings.ToLower(key) == "h" {
			// Remove ALL spaces from h= value, then let Split handle it
			// This handles cases like "from: to: subject:" correctly
			value = strings.ReplaceAll(value, " ", "")
		} else {
			// Remove internal whitespace from other values
			value = strings.Join(strings.Fields(value), "")
		}
		tags[key] = value
	}

	return tags
}

func stripDKIMB(header string) string {
	// This function name is misleading - just use stripDKIMBValue
	return stripDKIMBValue(header)
}

// Ensure sorted unused
var _ = sort.Strings
