package delivery

import (
	"strings"
	"testing"

	"gomail/parser"
)

func TestBuildDSNMessageRFC3464Structure(t *testing.T) {
	original := []byte("From: sender@example.com\nTo: missing@example.net\nSubject: Test\n\nsecret body\n")
	message, err := buildDSNMessage(
		"mx.example.com",
		"missing@example.net",
		"alias@example.net",
		"sender@example.com",
		"failed",
		"5.1.1 user unknown\r\nInjected: no",
		550,
		"envelope-123",
		"HDRS",
		original,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Auto-Submitted: auto-replied\r\n",
		"Content-Type: message/delivery-status\r\n",
		"Reporting-MTA: dns; mx.example.com\r\n",
		"Original-Envelope-Id: envelope-123\r\n",
		"Arrival-Date:",
		"\r\n\r\nOriginal-Recipient: rfc822; alias@example.net\r\n",
		"Final-Recipient: rfc822; missing@example.net\r\n",
		"Action: failed\r\n",
		"Status: 5.1.1\r\n",
		"Diagnostic-Code: smtp; 550 5.1.1 user unknown  Injected: no\r\n",
		"Content-Type: text/rfc822-headers\r\n",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("DSN missing %q:\n%s", want, message)
		}
	}
	if strings.Contains(message, "secret body") {
		t.Fatal("RET=HDRS leaked the original message body")
	}
	report, err := parser.ParseDSN(message)
	if err != nil {
		t.Fatalf("generated DSN did not parse: %v\n%s", err, message)
	}
	if report.Status != "5.1.1" || len(report.RecipientsStatus) != 1 {
		t.Fatalf("unexpected parsed report: %+v", report)
	}
}

func TestBuildDSNMessageReturnFull(t *testing.T) {
	message, err := buildDSNMessage("mx.example.com", "bad@example.net", "", "sender@example.com", "failed", "network failure", 0, "", "FULL", []byte("Subject: Test\r\n\r\noriginal body"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(message, "Content-Type: message/rfc822\r\n") || !strings.Contains(message, "original body") {
		t.Fatalf("RET=FULL did not include the complete message:\n%s", message)
	}
	if !strings.Contains(message, "Diagnostic-Code: X-GoMail; network failure\r\n") {
		t.Fatalf("network diagnostic missing:\n%s", message)
	}
}

func TestBuildDSNMessageSuccessAndDelay(t *testing.T) {
	original := []byte("Subject: Private\r\n\r\nsecret body")
	for _, tc := range []struct {
		action string
		code   int
		status string
	}{
		{action: "delivered", code: 250, status: "2.0.0"},
		{action: "delayed", code: 451, status: "4.3.2"},
	} {
		message, err := buildDSNMessage("mx.example", "user@example.net", "", "sender@example.org", tc.action, "delivery state", tc.code, "case-ID", "FULL", original)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"Action: " + tc.action, "Status: " + tc.status, "Original-Envelope-Id: case-ID", "Content-Type: text/rfc822-headers"} {
			if !strings.Contains(message, want) {
				t.Errorf("%s DSN missing %q:\n%s", tc.action, want, message)
			}
		}
		if strings.Contains(message, "secret body") {
			t.Errorf("%s DSN returned body despite non-failure action", tc.action)
		}
	}
}

func TestDSNNotifyContainsExactFlag(t *testing.T) {
	if !dsnNotifyContains("SUCCESS,DELAY", "DELAY") || dsnNotifyContains("FAILURE", "FAIL") {
		t.Fatal("DSN notification flag matching is not exact")
	}
}
