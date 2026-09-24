package handlers

import (
	"strings"
	"testing"
	"time"
)

func TestOriginatingHeadersPrivacySetting(t *testing.T) {
	date := time.Unix(1, 0)
	visible := originatingHeaders(false, "192.0.2.10", "mail.example.com", "id", "to@example.net", date)
	if !strings.Contains(visible, "192.0.2.10") || !strings.Contains(visible, "X-Originating-IP") {
		t.Fatalf("unstripped headers did not contain client address: %q", visible)
	}
	stripped := originatingHeaders(true, "192.0.2.10", "mail.example.com", "id", "to@example.net", date)
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
