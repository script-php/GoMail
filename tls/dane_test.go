package tlsconfig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"gomail/dns"
)

func makeChain(t *testing.T) ([]*x509.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "mail.example"}, DNSNames: []string{"mail.example"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafT, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return []*x509.Certificate{leaf, ca}, roots
}
func association(cert *x509.Certificate, selector, matching uint8) string {
	b := cert.Raw
	if selector == 1 {
		b = cert.RawSubjectPublicKeyInfo
	}
	if matching == 1 {
		s := sha256.Sum256(b)
		b = s[:]
	}
	if matching == 2 {
		s := sha512.Sum512(b)
		b = s[:]
	}
	return hex.EncodeToString(b)
}

func TestDANEUsageSelectorAndMatchingSemantics(t *testing.T) {
	chain, roots := makeChain(t)
	now := time.Now()
	for usage := uint8(0); usage <= 3; usage++ {
		for selector := uint8(0); selector <= 1; selector++ {
			for matching := uint8(0); matching <= 2; matching++ {
				name := fmt.Sprintf("usage-%d/selector-%d/matching-%d", usage, selector, matching)
				t.Run(name, func(t *testing.T) {
					candidate := chain[0]
					if usage == 0 || usage == 2 {
						candidate = chain[1]
					}
					record := dns.TLSARecord{Usage: usage, Selector: selector, MatchingType: matching, CertData: association(candidate, selector, matching)}
					got, err := VerifyDANECertificates("mail.example", chain, []dns.TLSARecord{record}, roots, now)
					if err != nil || !got.Matched || got.Usage != usage {
						t.Fatalf("got=%+v err=%v", got, err)
					}
				})
			}
		}
	}
}
func TestDANERejectsWrongHostForPKIXButAllowsDANEEE(t *testing.T) {
	chain, roots := makeChain(t)
	r := dns.TLSARecord{Usage: 1, Selector: 1, MatchingType: 1, CertData: association(chain[0], 1, 1)}
	got, err := VerifyDANECertificates("wrong.example", chain, []dns.TLSARecord{r}, roots, time.Now())
	if err != nil || got.Matched {
		t.Fatalf("PKIX-EE unexpectedly matched: %+v %v", got, err)
	}
	r.Usage = 3
	got, err = VerifyDANECertificates("wrong.example", chain, []dns.TLSARecord{r}, roots, time.Now())
	if err != nil || !got.Matched {
		t.Fatalf("DANE-EE did not match: %+v %v", got, err)
	}
}

func TestDANETARejectsWrongHost(t *testing.T) {
	chain, _ := makeChain(t)
	for _, selector := range []uint8{0, 1} {
		record := dns.TLSARecord{Usage: 2, Selector: selector, MatchingType: 1, CertData: association(chain[1], selector, 1)}
		got, err := VerifyDANECertificates("wrong.example", chain, []dns.TLSARecord{record}, nil, time.Now())
		if err != nil || got.Matched {
			t.Fatalf("DANE-TA selector %d accepted wrong-name leaf: %+v %v", selector, got, err)
		}
	}
}

func TestDANETAAcceptsAuthenticatedNextHopName(t *testing.T) {
	chain, _ := makeChain(t)
	record := dns.TLSARecord{Usage: 2, Selector: 0, MatchingType: 1, CertData: association(chain[1], 0, 1)}
	got, err := VerifyDANECertificates("mx.other.example", chain, []dns.TLSARecord{record}, nil, time.Now(), "mail.example")
	if err != nil || !got.Matched {
		t.Fatalf("DANE-TA rejected authenticated next-hop name: %+v %v", got, err)
	}
}
func TestDANERejectsMalformedMismatchAndUnlinkedTA(t *testing.T) {
	chain, roots := makeChain(t)
	bad := dns.TLSARecord{Usage: 3, Selector: 1, MatchingType: 1, CertData: "xyz"}
	if _, err := VerifyDANECertificates("mail.example", chain, []dns.TLSARecord{bad}, roots, time.Now()); err == nil {
		t.Fatal("expected malformed error")
	}
	mismatch := dns.TLSARecord{Usage: 3, Selector: 1, MatchingType: 1, CertData: stringsRepeat("00", 32)}
	got, err := VerifyDANECertificates("mail.example", chain, []dns.TLSARecord{mismatch}, roots, time.Now())
	if err != nil || got.Matched {
		t.Fatalf("mismatch got=%+v err=%v", got, err)
	}
	other, _ := makeChain(t)
	ta := dns.TLSARecord{Usage: 2, Selector: 1, MatchingType: 1, CertData: association(other[1], 1, 1)}
	got, err = VerifyDANECertificates("mail.example", append([]*x509.Certificate{chain[0]}, other[1]), []dns.TLSARecord{ta}, roots, time.Now())
	if err != nil || got.Matched {
		t.Fatalf("unlinked TA got=%+v err=%v", got, err)
	}
	valid := dns.TLSARecord{Usage: 3, Selector: 1, MatchingType: 1, CertData: association(chain[0], 1, 1)}
	got, err = VerifyDANECertificates("mail.example", chain, []dns.TLSARecord{bad, valid}, roots, time.Now())
	if err != nil || !got.Matched {
		t.Fatalf("valid record in mixed RRset was not accepted: got=%+v err=%v", got, err)
	}
}

func TestDANETAExactMatchAcceptsOmittedRoot(t *testing.T) {
	chain, roots := makeChain(t)
	_ = roots
	record := dns.TLSARecord{
		Usage:        2,
		Selector:     0,
		MatchingType: 0,
		CertData:     association(chain[1], 0, 0),
	}
	result, err := VerifyDANECertificates("mail.example", chain[:1], []dns.TLSARecord{record}, nil, time.Now())
	if err != nil || !result.Matched {
		t.Fatalf("omitted DANE trust anchor did not validate: result=%+v err=%v", result, err)
	}
}
func stringsRepeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
