package mdn

import (
	"net/mail"
	"strings"
	"testing"
)

func TestGeneratedMDNDoesNotInjectHeaders(t *testing.T) {
	for _, generate := range []func(string, string, string, string, string) string{GenerateMDN, GenerateMDNMultipart} {
		message := generate("<original@example.com>\r\nX-Injected: yes", "hello\r\nBcc: victim@example.com", "reader@example.com", "sender@example.com", "mail.example.com")
		parsed, err := mail.ReadMessage(strings.NewReader(message))
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Header.Get("Bcc") != "" || parsed.Header.Get("X-Injected") != "" {
			t.Fatal("untrusted MDN values created headers")
		}
		if !strings.Contains(parsed.Header.Get("Subject"), "Read: hello Bcc: victim@example.com") {
			t.Fatalf("subject lost or malformed: %q", parsed.Header.Get("Subject"))
		}
	}
}
