package reporting

import (
	"strings"
	"testing"
)

func TestDSNUsesGlobalStatusForUTF8Recipient(t *testing.T) {
	message, err := BuildDSNMessage("mail.example.test", "alice@example.test", "utf-8;josé+tag@example.test", "sender@example.test", "delivered", "delivered", 250, "", "HDRS", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(message, "Content-Type: message/global-delivery-status\r\n") || !strings.Contains(message, "Original-Recipient: utf-8; josé+tag@example.test\r\n") {
		t.Fatal("UTF-8 original recipient lacks global delivery-status representation")
	}
}

func TestDSNUsesGlobalTypesForUTF8FinalRecipientAndOriginalHeaders(t *testing.T) {
	original := []byte("From: álîce@example.test\r\nSubject: hello\r\n\r\nbody\r\n")
	message, err := BuildDSNMessage("mail.example.test", "josé@example.test", "", "sender@example.test", "failed", "mailbox unavailable", 550, "", "FULL", original)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Content-Type: message/global-delivery-status\r\n",
		"Final-Recipient: utf-8; josé@example.test\r\n",
		"Content-Type: message/global\r\n",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("UTF-8 DSN missing %q", want)
		}
	}
}

func TestDSNUsesGlobalHeadersForUTF8HeaderReturn(t *testing.T) {
	message, err := BuildDSNMessage("mail.example.test", "alice@example.test", "", "sender@example.test", "failed", "mailbox unavailable", 550, "", "HDRS", []byte("Subject: café\r\n\r\nprivate body"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(message, "Content-Type: message/global-headers\r\n") || strings.Contains(message, "private body") {
		t.Fatal("UTF-8 header-only return is incorrectly labeled or includes the body")
	}
}
