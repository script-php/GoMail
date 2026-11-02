package smtp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestSTSCertificateRequiresTrustedMatchingName(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mx.example"}, DNSNames: []string{"mx.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySTSCertificate([]*x509.Certificate{cert}, "mx.example", nil); err == nil {
		t.Fatal("untrusted DANE certificate satisfied MTA-STS")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if err := verifySTSCertificate([]*x509.Certificate{cert}, "mx.example", roots); err != nil {
		t.Fatal(err)
	}
	if err := verifySTSCertificate([]*x509.Certificate{cert}, "other.example", roots); err == nil {
		t.Fatal("wrong MX hostname satisfied MTA-STS")
	}
}
