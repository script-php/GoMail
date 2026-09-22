package tlsconfig

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"gomail/dns"
)

func GenerateTLSARecord(hostname string, cert *x509.Certificate) string {
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return fmt.Sprintf("_25._tcp.%s. IN TLSA 3 1 1 %s", hostname, hex.EncodeToString(h[:]))
}
func GenerateTLSARecordFromDER(hostname string, der []byte) (string, error) {
	cert, err := x509.ParseCertificate(der); if err != nil { return "", fmt.Errorf("parsing certificate: %w", err) }
	return GenerateTLSARecord(hostname, cert), nil
}

type DANEResult struct { Matched, RecordsPresent, DNSSECAuthenticated bool; Usage uint8; Details string }

func VerifyDANE(host string, conn *tls.Conn) (bool, string, error) {
	lookup, err := dns.LookupTLSA(host)
	if err != nil { return false, "TLSA lookup failed", err }
	if !lookup.Authenticated { return false, "TLSA response was not authenticated", dns.ErrDNSSECInsecure }
	if len(lookup.Records) == 0 { return false, "no authenticated TLSA records", nil }
	result, err := VerifyDANECertificates(host, conn.ConnectionState().PeerCertificates, lookup.Records, nil, time.Now())
	return result.Matched, result.Details, err
}

// VerifyDANECertificates implements RFC 6698 usage semantics. Usages 0/1 require
// PKIX validation. Usages 2/3 derive trust from DNSSEC-authenticated TLSA data.
func VerifyDANECertificates(host string, certs []*x509.Certificate, records []dns.TLSARecord, roots *x509.CertPool, now time.Time) (DANEResult, error) {
	result := DANEResult{RecordsPresent: len(records) > 0, DNSSECAuthenticated: true}
	if len(certs) == 0 { return result, fmt.Errorf("peer supplied no certificates") }
	intermediates := x509.NewCertPool(); for _, cert := range certs[1:] { intermediates.AddCert(cert) }
	pkixChains, pkixErr := certs[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: intermediates, CurrentTime: now})
	malformed := 0
	for _, record := range records {
		association, err := hex.DecodeString(record.CertData)
		if err != nil || record.Usage > 3 || record.Selector > 1 || record.MatchingType > 2 { malformed++; continue }
		switch record.Usage {
		case 0:
			if pkixErr == nil { for _, chain := range pkixChains { for _, cert := range chain[1:] { if matchCertificate(cert, record, association) { return matched(record, "PKIX-TA matched verified trust anchor"), nil } } } }
		case 1:
			if pkixErr == nil && matchCertificate(certs[0], record, association) { return matched(record, "PKIX-EE matched verified leaf"), nil }
		case 2:
			for i := 1; i < len(certs); i++ { if matchCertificate(certs[i], record, association) && chainLinksTo(certs, i, now) { return matched(record, "DANE-TA matched certificate chain trust anchor"), nil } }
		case 3:
			if matchCertificate(certs[0], record, association) { return matched(record, "DANE-EE matched leaf"), nil }
		}
	}
	if malformed == len(records) && len(records) > 0 { return result, fmt.Errorf("all TLSA records were malformed or unsupported") }
	if pkixErr != nil { result.Details = "no TLSA association matched (PKIX validation also failed: " + pkixErr.Error() + ")" } else { result.Details = "no TLSA association matched" }
	return result, nil
}
func matched(r dns.TLSARecord, details string) DANEResult { return DANEResult{Matched:true, RecordsPresent:true, DNSSECAuthenticated:true, Usage:r.Usage, Details:details} }
func matchCertificate(cert *x509.Certificate, record dns.TLSARecord, want []byte) bool {
	selected := cert.Raw; if record.Selector == 1 { selected = cert.RawSubjectPublicKeyInfo }
	switch record.MatchingType { case 0: return bytes.Equal(selected,want); case 1: s:=sha256.Sum256(selected); return bytes.Equal(s[:],want); case 2: s:=sha512.Sum512(selected); return bytes.Equal(s[:],want) }; return false
}
func chainLinksTo(certs []*x509.Certificate, anchor int, now time.Time) bool {
	for i:=0; i<=anchor; i++ { if now.Before(certs[i].NotBefore)||now.After(certs[i].NotAfter){return false}; if i<anchor && certs[i].CheckSignatureFrom(certs[i+1])!=nil{return false} }
	return certs[anchor].IsCA && certs[anchor].BasicConstraintsValid
}
