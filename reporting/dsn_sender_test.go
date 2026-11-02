package reporting

import (
	"strings"
	"testing"
)

func TestBuildDSNMessageWithSender(t *testing.T) {
	msg, err := BuildDSNMessageWithSender("mail.example.test", "bounces@example.test", "missing@remote.test", "", "sender@example.test", "failed", "rejected", 550, "", "HDRS", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "From: bounces@example.test\r\n") {
		t.Fatal("configured DSN sender missing")
	}
}
