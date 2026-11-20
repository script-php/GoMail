package smtp

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gomail/config"
	"gomail/store"
)

func TestInboundReceivedHeaderRecipientPrivacy(t *testing.T) {
	now := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	single := inboundReceivedHeader("mx.example", "192.0.2.1", []string{"alice@example.org"}, false, now)
	if !strings.Contains(single, "for <alice@example.org>;") {
		t.Fatalf("single recipient missing FOR clause: %q", single)
	}
	multi := inboundReceivedHeader("mx.example", "192.0.2.1", []string{"alice@example.org", "hidden@example.org"}, true, now)
	if strings.Contains(multi, "alice@example.org") || strings.Contains(multi, "hidden@example.org") || strings.Contains(multi, "for <") {
		t.Fatalf("multi-recipient Received header leaks recipients: %q", multi)
	}
}

func TestInboundReceivedHeaderUsesRegisteredTLSProtocolAndIPLiteral(t *testing.T) {
	got := inboundReceivedHeader("mx.example", "2001:db8::1", nil, true, time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC))
	if !strings.Contains(got, "from [IPv6:2001:db8::1]") || !strings.Contains(got, "with ESMTPS") {
		t.Fatalf("invalid Received trace: %q", got)
	}
}

func TestRemoveExternalAuthenticationResults(t *testing.T) {
	raw := []byte("From: a@example.test\r\nAuthentication-Results: mail.example.test; dkim=pass\r\n\tspf=pass\r\nSubject: intact\r\nAUTHENTICATION-RESULTS: other.test; dmarc=pass\r\n\r\nbody\r\nAuthentication-Results: body text\r\n")
	got, err := RemoveExternalAuthenticationResults(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bytes.ToLower(got[:bytes.Index(got, []byte("\r\n\r\n"))]), []byte("authentication-results:")) || !bytes.Contains(got, []byte("Subject: intact\r\n")) || !bytes.HasSuffix(got, []byte("Authentication-Results: body text\r\n")) {
		t.Fatalf("untrusted authentication header survived or message changed: %q", got)
	}
}

func TestFinalDeliveryReturnPathReplacesForgedFields(t *testing.T) {
	raw := []byte("From: sender@example.org\r\nReturn-Path: <forged@example.org>\r\n\tcontinued\r\nRETURN-PATH: <other@example.org>\r\nSubject: test\r\n\r\nBody\r\nReturn-Path: keep body text\r\n")
	got, err := FinalDeliveryReturnPath(raw, "bounce@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(got, []byte("Return-Path: <bounce@example.org>\r\n")) || bytes.Count(bytes.ToLower(got), []byte("return-path:")) != 2 {
		t.Fatalf("wrong Return-Path replacement: %q", got)
	}
	if bytes.Contains(got, []byte("forged@example.org")) || bytes.Contains(got, []byte("continued")) || bytes.Contains(got, []byte("other@example.org")) {
		t.Fatalf("forged Return-Path survived: %q", got)
	}
	if !bytes.HasSuffix(got, []byte("Body\r\nReturn-Path: keep body text\r\n")) {
		t.Fatalf("body changed: %q", got)
	}
}

func TestFinalDeliveryReturnPathNullReversePath(t *testing.T) {
	got, err := FinalDeliveryReturnPath([]byte("From: sender@example.org\r\n\r\nbody"), "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(got, []byte("Return-Path: <>\r\n")) {
		t.Fatalf("null reverse-path missing: %q", got)
	}
}

func TestFinalDeliveryReturnPathRejectsUnterminatedHeaders(t *testing.T) {
	if _, err := FinalDeliveryReturnPath([]byte("From: sender@example.test"), "sender@example.test"); err == nil {
		t.Fatal("accepted unterminated header-only message")
	}
}

func TestInboundStoredHeadersDoNotLeakEnvelopeRecipients(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	accountEmails := make(map[int64]string)
	for _, email := range []string{"alice@example.test", "hidden@example.test"} {
		accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: email, PasswordHash: "unused", IsActive: true})
		if err != nil {
			t.Fatal(err)
		}
		accountEmails[accountID] = email
	}
	sess := &Session{mailFrom: "bounce@remote.test", rcptTo: []string{"alice@example.test", "hidden@example.test"}, clientIP: "127.0.0.1", ehlo: "remote.test"}
	sess.data.WriteString("From: sender@remote.test\r\nTo: alice@example.test\r\nReturn-Path: <forged@remote.test>\r\nAuthentication-Results: forged.example; dkim=pass\r\nSubject: privacy\r\n\r\nhello\r\n")
	inbound := &InboundServer{cfg: &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test", Domain: "example.test"}}, db: db}
	if err := inbound.processMessage(sess); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(`SELECT raw_message, raw_headers, rcpt_to, account_id FROM messages`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var raw []byte
		var headers, recipients string
		var accountID int64
		if err := rows.Scan(&raw, &headers, &recipients, &accountID); err != nil {
			t.Fatal(err)
		}
		count++
		email := accountEmails[accountID]
		if email == "" || recipients != `["`+email+`"]` {
			t.Fatalf("mailbox %s can see other envelope recipients: %q", email, recipients)
		}
		if !bytes.HasPrefix(raw, []byte("Return-Path: <bounce@remote.test>\r\n")) || bytes.Contains(raw, []byte("forged@remote.test")) {
			t.Fatalf("stored reverse-path is not trusted: %q", raw)
		}
		if bytes.Contains(raw, []byte("forged.example; dkim=pass")) || !bytes.Contains(raw, []byte("Authentication-Results: mail.example.test;")) {
			t.Fatalf("stored authentication results are not trusted: %q", raw)
		}
		if !strings.Contains(headers, "Return-Path: <bounce@remote.test>") || strings.Contains(headers, "forged@remote.test") {
			t.Fatalf("stored header metadata has wrong reverse-path: %q", headers)
		}
		receivedStart := bytes.Index(raw, []byte("\r\nReceived:"))
		receivedEnd := bytes.Index(raw, []byte("\r\nFrom: sender@remote.test"))
		if receivedStart < 0 || receivedEnd < receivedStart {
			t.Fatalf("Received header boundary missing: %q", raw)
		}
		received := raw[receivedStart:receivedEnd]
		if bytes.Contains(received, []byte("hidden@example.test")) || bytes.Contains(received, []byte("for <")) {
			t.Fatalf("Received header leaks envelope recipients: %q", received)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("stored %d messages, want 2", count)
	}
}
