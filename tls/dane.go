package tlsconfig

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
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
