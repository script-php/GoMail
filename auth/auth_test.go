package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestGeneratedEd25519DKIMRecordUsesRawPublicKey(t *testing.T) {
	_, _, record, err := GenerateDKIMKeyPair("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	tags := parseDKIMTags(record)
	raw, err := base64.StdEncoding.DecodeString(tags["p"])
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 32 {
		t.Fatalf("published key has %d bytes, want 32", len(raw))
	}
	parsed := parseDKIMRecord(record)
	if parsed == nil || parsed.PublicKey == nil {
		t.Fatal("generated DNS record cannot be parsed by verifier")
	}
}

func TestAuthenticationResultsIncludesDKIMIdentity(t *testing.T) {
	b := NewAuthResultsBuilder("mx.example")
	b.AddDKIM("pass", "valid", "example.com", "mail")
	got := b.Build()
	for _, want := range []string{"mx.example;", "dkim=pass", "header.d=example.com", "header.s=mail"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}
}

func TestAuthenticationResultsCannotInjectHeaders(t *testing.T) {
	b := NewAuthResultsBuilder("mx.example")
	b.AddDKIM("fail", "bad)\r\nX-Evil: yes", "evil; injected", "s")
	got := b.Build()
	if strings.Contains(got, "\r\nX-Evil") || strings.Contains(got, "header.d=evil;") {
		t.Fatalf("unsafe result: %q", got)
	}
}

func TestDMARCOrganizationalDomain(t *testing.T) {
	if got := getOrgDomain("mail.example.co.uk"); got != "example.co.uk" {
		t.Fatalf("got %q", got)
	}
	if !checkAlignment("news.example.co.uk", "bounce.example.co.uk", "r") {
		t.Fatal("relaxed alignment failed")
	}
	if checkAlignment("news.example.co.uk", "bounce.example.co.uk", "s") {
		t.Fatal("strict alignment passed")
	}
}

func TestARCMessageSignatureSupportsEd25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("From: a@example.com\r\nTo: b@example.net\r\nSubject: test\r\nDate: Tue, 1 Jan 2030 00:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\nbody\r\n")
	_, err = ARCMessageSignature(&ARCMessageSignatureInput{Instance: 1, Selector: "mail", Domain: "example.com", PrivateKey: priv, Message: msg, BodyHash: BodyHash("body\r\n")})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSPFMechanismSyntax(t *testing.T) {
	for _, valid := range []string{"all", "a", "mx:example.com/24", "ip4:192.0.2.0/24", "ip6:2001:db8::/32", "include:example.com", "exists:%{i}.example.com"} {
		if err := validateSPFMechanism(valid); err != nil {
			t.Errorf("%s: %v", valid, err)
		}
	}
	for _, invalid := range []string{"wat:example.com", "ip4:999.1.1.1", "ip6:192.0.2.1"} {
		if err := validateSPFMechanism(invalid); err == nil {
			t.Errorf("accepted %s", invalid)
		}
	}
}

func TestDKIMSignVerifyAndMultipleSignatures(t *testing.T) {
	private, _, record, err := GenerateDKIMKeyPair("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewDKIMSignerFromPEM("example.com", "mail", []byte(private), "ed25519")
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("From: a@example.com\r\nTo: b@example.net\r\nSubject: hello\r\nDate: Tue, 1 Jan 2030 00:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\nbody\r\n")
	signed, err := signer.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	old := lookupTXT
	lookupTXT = func(name string) ([]string, error) {
		if name != "mail._domainkey.example.com" {
			return nil, fmt.Errorf("unexpected query %s", name)
		}
		return []string{record}, nil
	}
	t.Cleanup(func() { lookupTXT = old })
	status, detail, domain, selector := VerifyDKIMDetailed(signed)
	if status != "pass" {
		t.Fatalf("status=%s detail=%s", status, detail)
	}
	if domain != "example.com" || selector != "mail" {
		t.Fatalf("identity %s/%s", domain, selector)
	}
	broken := append([]byte("DKIM-Signature: v=1; a=rsa-sha256; d=bad.example; s=x; b=bad\r\n"), signed...)
	status, detail, domain, selector = VerifyDKIMDetailed(broken)
	if status != "pass" {
		t.Fatalf("second signature not tried: %s %s", status, detail)
	}
}

func TestDMARCAlignmentAndPolicyDiscovery(t *testing.T) {
	old := lookupTXT
	lookupTXT = func(name string) ([]string, error) {
		switch name {
		case "_dmarc.news.example.co.uk":
			return nil, &net.DNSError{IsNotFound: true}
		case "_dmarc.example.co.uk":
			return []string{"v=DMARC1; p=reject; adkim=s; aspf=r"}, nil
		}
		return nil, &net.DNSError{IsNotFound: true}
	}
	t.Cleanup(func() { lookupTXT = old })
	got := CheckDMARC("news.example.co.uk", SPFPass, "bounce.example.co.uk", "fail", "")
	if got.Result != DMARCPass || got.Policy != PolicyReject {
		t.Fatalf("unexpected result: %+v", got)
	}
	got = CheckDMARC("news.example.co.uk", SPFFail, "bounce.example.co.uk", "pass", "mail.example.co.uk")
	if got.Result != DMARCFail {
		t.Fatalf("strict DKIM alignment unexpectedly passed: %+v", got)
	}
}

func TestDMARCMultipleRecordsArePermError(t *testing.T) {
	old := lookupTXT
	lookupTXT = func(string) ([]string, error) { return []string{"v=DMARC1; p=none", "v=DMARC1; p=reject"}, nil }
	t.Cleanup(func() { lookupTXT = old })
	got := CheckDMARC("example.com", SPFFail, "bad.example", "fail", "")
	if got.Result != DMARCPermError {
		t.Fatalf("got %+v", got)
	}
}

func TestSPFResultsAndNullReversePath(t *testing.T) {
	old := lookupTXT
	defer func() { lookupTXT = old }()
	lookupTXT = func(name string) ([]string, error) {
		if name == "example.com" {
			return []string{"v=spf1 ip4:192.0.2.0/24 -all"}, nil
		}
		return nil, &net.DNSError{IsNotFound: true}
	}
	if result, _ := CheckSPF("192.0.2.10", "sender@example.com"); result != SPFPass {
		t.Fatalf("got %s", result)
	}
	if result, _ := CheckSPF("198.51.100.2", "sender@example.com"); result != SPFFail {
		t.Fatalf("got %s", result)
	}
	if result, _ := CheckSPFWithHELO("192.0.2.10", "", "example.com"); result != SPFPass {
		t.Fatalf("null reverse path got %s", result)
	}
	lookupTXT = func(string) ([]string, error) { return []string{"v=spf1 -all", "v=spf1 +all"}, nil }
	if result, _ := CheckSPF("192.0.2.1", "a@example.com"); result != SPFPermError {
		t.Fatalf("duplicate records got %s", result)
	}
	lookupTXT = func(string) ([]string, error) { return nil, &net.DNSError{IsTimeout: true, IsTemporary: true} }
	if result, _ := CheckSPF("192.0.2.1", "a@example.com"); result != SPFTempError {
		t.Fatalf("timeout got %s", result)
	}
}
