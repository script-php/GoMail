package parser

import (
	"strings"
	"testing"
)

func TestParseDSNMultipartWithComplexBoundaryAndFoldedFields(t *testing.T) {
	raw := strings.Join([]string{
		"From: mailer-daemon@example.net",
		"To: sender@example.org",
		"Subject: Delivery Status Notification",
		"MIME-Version: 1.0",
		"Content-Type: multipart/report; report-type=delivery-status; boundary=\"=_dsn.boundary+123\"",
		"",
		"--=_dsn.boundary+123",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"One recipient failed.",
		"--=_dsn.boundary+123",
		"Content-Type: message/delivery-status",
		"",
		"Reporting-MTA: dns; mx.example.net",
		"Original-Message-ID: <original@example.org>",
		"",
		"Original-Recipient: rfc822; alias@example.net",
		"Final-Recipient: rfc822; first@example.net",
		"Action: failed",
		"Status: 5.1.1",
		"Diagnostic-Code: smtp; 550 5.1.1",
		" user unknown",
		"Remote-MTA: dns; remote.example.net",
		"",
		"Final-Recipient: rfc822; second@example.net",
		"Action: delayed",
		"Status: 4.2.0",
		"Diagnostic-Code: smtp; 451 retry later",
		"",
		"--=_dsn.boundary+123",
		"Content-Type: message/rfc822",
		"",
		"Subject: original",
		"",
		"--not-a-real-boundary--",
		"--=_dsn.boundary+123--",
		"",
	}, "\r\n")
	report, err := ParseDSN(raw)
	if err != nil {
		t.Fatal(err)
	}
	if report.OriginalMessageID != "<original@example.org>" || report.Action != "failed" || report.Status != "5.1.1" {
		t.Fatalf("incorrect report-level fields: %+v", report)
	}
	if report.OriginalRecipient != "alias@example.net" || len(report.RecipientsStatus) != 2 {
		t.Fatalf("incorrect recipients: %+v", report)
	}
	if got := report.RecipientsStatus[0].DiagnosticCode; got != "smtp; 550 5.1.1 user unknown" {
		t.Fatalf("folded diagnostic = %q", got)
	}
	if got := report.RecipientsStatus[1].FinalRecipient; got != "second@example.net" {
		t.Fatalf("second recipient = %q", got)
	}
}

func TestParseDSNRecipientBlocksWithoutBlankSeparator(t *testing.T) {
	body := "Final-Recipient: rfc822; one@example.net\r\nAction: failed\r\nStatus: 5.1.1\r\nFinal-Recipient: rfc822; two@example.net\r\nAction: failed\r\nStatus: 5.1.2\r\n"
	report, err := ParseDSN(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.RecipientsStatus) != 2 || report.RecipientsStatus[1].Status != "5.1.2" {
		t.Fatalf("recipient blocks not separated: %+v", report.RecipientsStatus)
	}
}

func TestExtractBounceTypeIncludesSuccess(t *testing.T) {
	for input, want := range map[string]string{"2.0.0": "success", "4.2.0": "temporary", "5.1.1": "permanent", "bad": "unknown"} {
		if got := ExtractBounceType(input); got != want {
			t.Errorf("ExtractBounceType(%q) = %q, want %q", input, got, want)
		}
	}
}
