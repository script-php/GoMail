package auth

import (
	"bytes"
	"fmt"
	"testing"
)

func TestDKIMProtectsTLSReportIdentityHeaders(t *testing.T) {
	private, _, record, err := GenerateDKIMKeyPair("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewDKIMSignerFromPEM("sender.example", "mail", []byte(private), "ed25519")
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("From: reports@sender.example\r\nTo: rua@receiver.example\r\nSubject: TLS report\r\nDate: Tue, 1 Jan 2030 00:00:00 +0000\r\nMessage-ID: <1@sender.example>\r\nTLS-Report-Domain: receiver.example\r\nTLS-Report-Submitter: sender.example\r\n\r\nreport\r\n")
	signed, err := signer.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	oldLookup := lookupTXT
	lookupTXT = func(name string) ([]string, error) {
		if name != "mail._domainkey.sender.example" {
			return nil, fmt.Errorf("unexpected DKIM query %s", name)
		}
		return []string{record}, nil
	}
	t.Cleanup(func() { lookupTXT = oldLookup })
	if status, detail := VerifyDKIM(signed); status != "pass" {
		t.Fatalf("valid TLS report signature: %s (%s)", status, detail)
	}
	for _, change := range []struct{ before, after string }{
		{"TLS-Report-Domain: receiver.example", "TLS-Report-Domain: other.example"},
		{"TLS-Report-Submitter: sender.example", "TLS-Report-Submitter: other.example"},
	} {
		modified := bytes.Replace(signed, []byte(change.before), []byte(change.after), 1)
		if bytes.Equal(modified, signed) {
			t.Fatalf("header %q not found in signed message", change.before)
		}
		if status, _ := VerifyDKIM(modified); status == "pass" {
			t.Fatalf("altered TLS-RPT identity header still passed DKIM: %q", change.before)
		}
	}
}
