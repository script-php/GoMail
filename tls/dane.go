package tlsconfig

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"

	"gomail/dns"
)

// GenerateTLSARecord generates a TLSA record (DANE) for the server's certificate.
// Usage 3 (DANE-EE), Selector 1 (SubjectPublicKeyInfo), Matching Type 1 (SHA-256).
// Returns the record in the format: _25._tcp.hostname TLSA 3 1 1 <hash>
func GenerateTLSARecord(hostname string, cert *x509.Certificate) string {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Sprintf("; error marshaling public key: %v", err)
	}

	hash := sha256.Sum256(pubKeyDER)
	hexHash := hex.EncodeToString(hash[:])

	return fmt.Sprintf("_25._tcp.%s. IN TLSA 3 1 1 %s", hostname, hexHash)
}

// GenerateTLSARecordFromDER generates a TLSA record from raw DER certificate bytes.
func GenerateTLSARecordFromDER(hostname string, certDER []byte) (string, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("parsing certificate: %w", err)
	}
	return GenerateTLSARecord(hostname, cert), nil
}

// VerifyDANE verifies a certificate against TLSA records (DANE verification).
// Returns (isValid, details, error):
// - isValid: true if DANE verification passes
// - details: explanation of verification result
// - error: only non-nil if TLSA lookup fails (not if verification fails)
//
// Per RFC 6698, DANE provides DNSSEC-based certificate pinning.
// Returns (false, "no TLSA records", nil) if no TLSA records exist (fallback to standard TLS).
func VerifyDANE(host string, tlsConn *tls.Conn) (bool, string, error) {
	if host == "" {
		return false, "empty host", nil
	}

	// Look up TLSA records for the host
	tlsaRecords, err := dns.LookupTLSA(host)
	if err != nil {
		log.Printf("[dane] TLSA lookup failed for %s: %v (falling back to standard TLS)", host, err)
		return false, fmt.Sprintf("TLSA lookup failed: %v", err), nil
	}

	// No TLSA records means fallback to standard TLS verification
	if len(tlsaRecords) == 0 {
		log.Printf("[dane] no TLSA records for %s (DANE not available, using standard TLS)", host)
		return false, "no TLSA records found (DANE not configured)", nil
	}

	// Get the peer certificate from the TLS connection
	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return false, "no peer certificate in TLS connection", fmt.Errorf("TLS connection has no peer certificate")
	}

	peerCert := peerCerts[0]
	log.Printf("[dane] verifying certificate for %s against %d TLSA records", host, len(tlsaRecords))

	// Try to match certificate against any TLSA record
	for i, tlsaRecord := range tlsaRecords {
		if isDANEMatch(peerCert, tlsaRecord) {
			log.Printf("[dane] TLSA record %d matched for %s (usage=%d, selector=%d, type=%d)",
				i, host, tlsaRecord.Usage, tlsaRecord.Selector, tlsaRecord.MatchingType)
			return true, fmt.Sprintf("DANE verified via TLSA record %d", i), nil
		}
		log.Printf("[dane] TLSA record %d did not match for %s", i, host)
	}

	// If any TLSA records exist but none match, verification fails
	return false, fmt.Sprintf("certificate does not match any of %d TLSA records", len(tlsaRecords)), nil
}

// isDANEMatch checks if a certificate matches a TLSA record.
// Implements RFC 6698 certificate matching based on Usage, Selector, and MatchingType.
func isDANEMatch(cert *x509.Certificate, tlsa dns.TLSARecord) bool {
	var certData []byte

	switch tlsa.Selector {
	case 0: // Full certificate
		certData = cert.Raw
	case 1: // Public key only (SubjectPublicKeyInfo)
		pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			log.Printf("[dane] error marshaling public key: %v", err)
			return false
		}
		certData = pubKeyDER
	default:
		log.Printf("[dane] unknown selector %d", tlsa.Selector)
		return false
	}

	// Compute hash of certificate data
	var computedHash string
	switch tlsa.MatchingType {
	case 0: // Exact match (no hashing)
		computedHash = hex.EncodeToString(certData)
	case 1: // SHA-256
		hash := sha256.Sum256(certData)
		computedHash = hex.EncodeToString(hash[:])
	case 2: // SHA-512
		hash := sha512.Sum512(certData)
		computedHash = hex.EncodeToString(hash[:])
	default:
		log.Printf("[dane] unknown matching type %d", tlsa.MatchingType)
		return false
	}

	// Compare with TLSA record hash
	if computedHash == tlsa.CertData {
		log.Printf("[dane] certificate hash matches TLSA record")
		return true
	}

	log.Printf("[dane] certificate hash mismatch: computed=%s, tlsa=%s", computedHash[:16]+"...", tlsa.CertData[:16]+"...")
	return false
}
