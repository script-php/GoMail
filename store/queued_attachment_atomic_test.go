package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQueuedAttachmentsCommitWithSentCopy(t *testing.T) {
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
	sent, err := db.GetFolderByType(accountID, "sent")
	if err != nil || sent == nil {
		t.Fatalf("sent folder=%v err=%v", sent, err)
	}
	message := func() *Message {
		return &Message{AccountID: accountID, FolderID: &sent.ID, MessageID: "outbound-sidecar", Direction: "outbound", RawMessage: []byte("From: alice@example.test\r\n\r\nbody\r\n"), HasAttachments: true, ReceivedAt: time.Now()}
	}
	entries := func() []*QueueEntry {
		return []*QueueEntry{{MailFrom: "alice@example.test", RcptTo: "bob@remote.test", RawMessage: []byte("From: alice@example.test\r\n\r\nbody\r\n"), MaxAttempts: 3, NextRetry: time.Now()}}
	}
	attachments := []IMAPAppendAttachment{{Filename: "report.txt", ContentType: "text/plain", Data: []byte("payload")}}
	if _, err := db.Exec(`CREATE TRIGGER fail_sent_attachment BEFORE INSERT ON attachments BEGIN SELECT RAISE(FAIL, 'sidecar unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveQueuedMessageWithAttachments(message(), entries(), attachments); err == nil {
		t.Fatal("queued message despite sidecar failure")
	}
	var sentCount, queueCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE message_id='outbound-sidecar'`).Scan(&sentCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM outbound_queue WHERE mail_from='alice@example.test'`).Scan(&queueCount); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(db.AttachmentsPath())
	if err != nil || sentCount != 0 || queueCount != 0 || len(files) != 0 {
		t.Fatalf("partial outbound commit: sent=%d queue=%d files=%d err=%v", sentCount, queueCount, len(files), err)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_sent_attachment`); err != nil {
		t.Fatal(err)
	}
	id, err := db.SaveQueuedMessageWithAttachments(message(), entries(), attachments)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := db.GetAttachments(id)
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored sidecars=%d err=%v", len(stored), err)
	}
	updatedSent, err := db.GetFolderByType(accountID, "sent")
	if err != nil || updatedSent.TotalCount != 1 {
		t.Fatalf("Sent count was not committed with message: %+v, %v", updatedSent, err)
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_sent_count BEFORE UPDATE OF total_count ON folders
		WHEN NEW.total_count > 1 BEGIN SELECT RAISE(FAIL, 'sent count unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveQueuedMessageWithAttachments(message(), entries(), attachments); err == nil {
		t.Fatal("outbound queue committed without Sent count")
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE account_id=?`, accountID).Scan(&sentCount); err != nil || sentCount != 1 {
		t.Fatalf("failed Sent count update left message: %d, %v", sentCount, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM outbound_queue WHERE mail_from='alice@example.test'`).Scan(&queueCount); err != nil || queueCount != 1 {
		t.Fatalf("failed Sent count update left queue entry: %d, %v", queueCount, err)
	}
}
