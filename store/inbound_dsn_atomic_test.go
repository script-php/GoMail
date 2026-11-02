package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestInboundDeliveryAndRequestedDSNAreAtomic(t *testing.T) {
	root := t.TempDir()
	db, err := Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&Account{DomainID: domainID, Email: "alice@example.test", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	message := &Message{AccountID: accountID, MessageID: "inbound-dsn-test", Direction: "inbound", MailFrom: "sender@remote.test", RawMessage: []byte("From: sender@remote.test\r\n\r\nbody\r\n"), ReceivedAt: time.Now()}
	report := &QueueEntry{MailFrom: "", RcptTo: "sender@remote.test", RawMessage: []byte("From: Mailer-Daemon@example.test\r\n\r\nreport\r\n"), MaxAttempts: 3, NextRetry: time.Now(), DSNNotify: "NEVER"}
	if _, err := db.Exec(`CREATE TRIGGER fail_report BEFORE INSERT ON outbound_queue BEGIN SELECT RAISE(FAIL, 'queue unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveMessagesWithQueue([]*Message{message}, []*QueueEntry{report}); err == nil {
		t.Fatal("delivery committed despite DSN queue failure")
	}
	var messages int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE message_id = ?`, message.MessageID).Scan(&messages); err != nil || messages != 0 {
		t.Fatalf("messages after rollback=%d err=%v", messages, err)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_report`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveMessagesWithQueue([]*Message{message}, []*QueueEntry{report}); err != nil {
		t.Fatal(err)
	}
	var queued int
	if err := db.QueryRow(`SELECT COUNT(*) FROM outbound_queue WHERE rcpt_to = ? AND mail_from = ''`, report.RcptTo).Scan(&queued); err != nil || queued != 1 {
		t.Fatalf("queued DSNs=%d err=%v", queued, err)
	}
}
