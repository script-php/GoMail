package mailclient

import (
	"bytes"
	"gomail/config"
	"testing"
)

func TestTopMessage(t *testing.T) {
	raw := []byte("From: user@example.com\nSubject: test\n\nfirst\n.second\nthird\n")
	got := topMessage(raw, 2)
	want := []byte("From: user@example.com\r\nSubject: test\r\n\r\nfirst\r\n.second")
	if !bytes.Equal(got, want) {
		t.Fatalf("TOP mismatch:\n%q\nwant:\n%q", got, want)
	}
}

func TestParsePath(t *testing.T) {
	address, rest, ok := parsePath("FROM:<user@example.com> SIZE=12 BODY=8BITMIME", "FROM:")
	if !ok || address != "user@example.com" || rest != "SIZE=12 BODY=8BITMIME" {
		t.Fatalf("unexpected path: %q %q %v", address, rest, ok)
	}
	for _, malformed := range []string{"user@example.com", "FROM:user@example.com", "FROM:<>"} {
		if _, _, ok := parsePath(malformed, "FROM:"); ok {
			t.Fatalf("accepted malformed path %q", malformed)
		}
	}
}

func TestValidateSubmittedFrom(t *testing.T) {
	valid := []byte("From: Person <user@example.com>\r\nTo: x@example.net\r\n\r\nhello\r\n")
	if err := validateSubmittedFrom(valid, "USER@example.com"); err != nil {
		t.Fatal(err)
	}
	invalid := []byte("From: attacker@example.net\r\n\r\nhello\r\n")
	if err := validateSubmittedFrom(invalid, "user@example.com"); err == nil {
		t.Fatal("accepted a spoofed From header")
	}
}

func TestStripBccIncludingContinuation(t *testing.T) {
	raw := []byte("From: user@example.com\r\nBcc: hidden@example.net,\r\n next@example.net\r\nSubject: test\r\n\r\nbody\r\n")
	got := stripHeader(raw, "bcc")
	if bytes.Contains(bytes.ToLower(got), []byte("bcc:")) || bytes.Contains(got, []byte("next@example.net")) {
		t.Fatalf("Bcc was not removed: %q", got)
	}
	if !bytes.Contains(got, []byte("Subject: test")) || !bytes.Contains(got, []byte("body")) {
		t.Fatalf("unrelated content was removed: %q", got)
	}
}

func TestNormalizeCRLF(t *testing.T) {
	got := normalizeCRLF([]byte("a\rb\nc\r\nd"))
	if string(got) != "a\r\nb\r\nc\r\nd" {
		t.Fatalf("got %q", got)
	}
}

func TestAuthenticationRateLimit(t *testing.T) {
	server := NewServer(&config.Config{Clients: config.MailClientsConfig{MaxConnections: 1, AuthAttempts: 2}}, nil, nil, nil)
	if !server.allowAuthentication("192.0.2.1:1000") || !server.allowAuthentication("192.0.2.1:1001") {
		t.Fatal("allowed attempts were rejected")
	}
	if server.allowAuthentication("192.0.2.1:1002") {
		t.Fatal("excess authentication attempt was allowed")
	}
	if !server.allowAuthentication("192.0.2.2:1000") {
		t.Fatal("one IP incorrectly affected another")
	}
}
