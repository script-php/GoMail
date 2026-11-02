package handlers

import (
	"mime"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLongNonASCIIHeaderUsesBoundedEncodedWords(t *testing.T) {
	value := strings.Repeat("é", 60)
	header := formatUnstructuredHeader("Subject", value)
	for _, word := range strings.Fields(strings.TrimPrefix(strings.TrimSpace(header), "Subject:")) {
		if strings.HasPrefix(word, "=?") && len(word) > 75 {
			t.Fatalf("RFC 2047 encoded-word is %d characters", len(word))
		}
	}
	decoded, err := new(mime.WordDecoder).DecodeHeader(strings.TrimSpace(strings.TrimPrefix(header, "Subject:")))
	if err != nil || decoded != value {
		t.Fatalf("subject round trip: %q, %v", decoded, err)
	}
	for _, line := range strings.Split(header, "\r\n") {
		if len(line)+2 > 1000 {
			t.Fatalf("overlong SMTP header line: %d", len(line)+2)
		}
	}
}

func TestOriginatingIPIgnoresProviderHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.9:1234"
	r.Header.Set("CF-Connecting-IP", "198.51.100.66")
	if got := getRealClientIP(r); got != "203.0.113.9" {
		t.Fatalf("untrusted provider header selected client IP: %q", got)
	}
	r.RemoteAddr = "[2001:db8::9]:1234"
	if got := getRealClientIP(r); got != "2001:db8::9" {
		t.Fatalf("IPv6 peer parsed incorrectly: %q", got)
	}
}

func TestOriginatingHeadersPrivacySetting(t *testing.T) {
	date := time.Unix(1, 0)
	visible := originatingHeaders(false, "192.0.2.10", "mail.example.com", "id", []string{"to@example.net"}, date)
	if !strings.Contains(visible, "192.0.2.10") || !strings.Contains(visible, "X-Originating-IP") {
		t.Fatalf("unstripped headers did not contain client address: %q", visible)
	}
	stripped := originatingHeaders(true, "192.0.2.10", "mail.example.com", "id", []string{"to@example.net"}, date)
	if strings.Contains(stripped, "192.0.2.10") || strings.Contains(stripped, "X-Originating-IP") {
		t.Fatalf("privacy setting leaked client address: %q", stripped)
	}
}

func TestEncodeHeaderValuePreventsHeaderInjection(t *testing.T) {
	got := encodeHeaderValue("hello\r\nBcc: attacker@example.net")
	if strings.ContainsAny(got, "\r\n") || !strings.Contains(got, "Bcc: attacker@example.net") {
		t.Fatalf("unsafe or unexpected header value: %q", got)
	}
}

func TestRecipientParsingRejectsCommandAndHeaderInjection(t *testing.T) {
	for _, malicious := range []string{
		"victim@example.net\r\nBcc: attacker@example.net",
		"victim@example.net\nDATA",
		"not-an-address",
		"victim@example.net, broken",
	} {
		if recipients, err := parseRecipients(malicious); err == nil {
			t.Fatalf("accepted malicious recipient %q as %#v", malicious, recipients)
		}
	}
	recipients, err := parseRecipients("Person <person@example.net>; second@example.org")
	if err != nil || len(recipients) != 2 || recipients[0] != "person@example.net" || recipients[1] != "second@example.org" {
		t.Fatalf("valid recipients failed: %#v %v", recipients, err)
	}
}

func TestOriginatingHeadersForceSingleLineValues(t *testing.T) {
	got := originatingHeaders(false, "192.0.2.1\r\nInjected: yes", "mail.example", "id\nX: y", []string{"to@example\r\nBcc: bad@example"}, time.Unix(1, 0))
	if strings.Contains(got, "\r\nInjected:") || strings.Contains(got, "\nX:") || strings.Contains(got, "\r\nBcc:") {
		t.Fatalf("generated header accepted injected field: %q", got)
	}
}

func TestOriginatingHeadersOmitForForMultipleRecipients(t *testing.T) {
	date := time.Unix(1, 0)
	for _, strip := range []bool{false, true} {
		got := originatingHeaders(strip, "192.0.2.10", "mail.example.com", "id", []string{"to@example.net", "blind@example.net"}, date)
		if strings.Contains(got, "blind@example.net") || strings.Contains(got, "for <") {
			t.Fatalf("multi-recipient trace leaked recipient: %q", got)
		}
		one := originatingHeaders(strip, "192.0.2.10", "mail.example.com", "id", []string{"to@example.net"}, date)
		if !strings.Contains(one, "for <to@example.net>") {
			t.Fatalf("single-recipient trace omitted FOR: %q", one)
		}
	}
}
