package store

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInboundAttachmentWriteIgnoresOrphanFromInterruptedCommit(t *testing.T) {
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
	data := []byte("payload")
	digest := sha256.Sum256(data)
	orphanName := fmt.Sprintf("1_inbound_0_%x.txt", digest[:8])
	if err := os.WriteFile(filepath.Join(db.AttachmentsPath(), orphanName), []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	message := &Message{AccountID: accountID, MessageID: "orphan-retry", Direction: "inbound", RawMessage: []byte("From: sender@remote.test\r\n\r\nbody\r\n"), HasAttachments: true, ReceivedAt: time.Now()}
	ids, err := db.SaveMessagesWithQueueAndAttachments([]*Message{message}, nil, [][]IMAPAppendAttachment{{{Filename: "document.txt", ContentType: "text/plain", Data: data}}})
	if err != nil {
		t.Fatalf("orphan blocked delivery: %v", err)
	}
	attachments, err := db.GetAttachments(ids[0])
	if err != nil || len(attachments) != 1 || attachments[0].StoragePath == orphanName {
		t.Fatalf("delivery reused orphan: %+v, %v", attachments, err)
	}
	stored, err := os.ReadFile(filepath.Join(db.AttachmentsPath(), attachments[0].StoragePath))
	if err != nil || string(stored) != string(data) {
		t.Fatalf("delivered attachment: %q, %v", stored, err)
	}
}

func TestInboundDeliveryCommitsFolderCountsOrRollsBack(t *testing.T) {
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
	inbox, err := db.GetFolderByType(accountID, "inbox")
	if err != nil || inbox == nil {
		t.Fatalf("inbox: %+v, %v", inbox, err)
	}
	newMessage := func(id string) *Message {
		return &Message{AccountID: accountID, FolderID: &inbox.ID, MessageID: id, Direction: "inbound", RawMessage: []byte("From: sender@remote.test\r\n\r\nbody\r\n"), ReceivedAt: time.Now()}
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_folder_count BEFORE UPDATE OF total_count ON folders
		WHEN NEW.total_count > 0 BEGIN SELECT RAISE(FAIL, 'folder count unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveInboundDelivery([]*Message{newMessage("first")}, nil, nil, nil); err == nil {
		t.Fatal("delivery committed without folder count")
	}
	var messages int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE account_id=?`, accountID).Scan(&messages); err != nil || messages != 0 {
		t.Fatalf("failed delivery left message: %d, %v", messages, err)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_folder_count`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveInboundDelivery([]*Message{newMessage("second")}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	updated, err := db.GetFolderByType(accountID, "inbox")
	if err != nil || updated.TotalCount != 1 || updated.UnreadCount != 1 {
		t.Fatalf("committed folder counts: %+v, %v", updated, err)
	}
}

func TestInboundAttachmentsCommitOrRollbackWithMessage(t *testing.T) {
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
	newMessage := func() *Message {
		return &Message{AccountID: accountID, MessageID: "attachment-test", Direction: "inbound", RawMessage: []byte("From: sender@remote.test\r\n\r\nbody\r\n"), HasAttachments: true, ReceivedAt: time.Now()}
	}
	batch := [][]IMAPAppendAttachment{{{Filename: "document.txt", ContentType: "text/plain", Data: []byte("payload")}}}
	if _, err := db.Exec(`CREATE TRIGGER fail_attachment BEFORE INSERT ON attachments BEGIN SELECT RAISE(FAIL, 'attachment unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveMessagesWithQueueAndAttachments([]*Message{newMessage()}, nil, batch); err == nil {
		t.Fatal("message committed despite attachment failure")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE message_id='attachment-test'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("messages after rollback=%d err=%v", count, err)
	}
	files, err := os.ReadDir(db.AttachmentsPath())
	if err != nil || len(files) != 0 {
		t.Fatalf("attachment files after rollback=%d err=%v", len(files), err)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_attachment`); err != nil {
		t.Fatal(err)
	}
	ids, err := db.SaveMessagesWithQueueAndAttachments([]*Message{newMessage()}, nil, batch)
	if err != nil {
		t.Fatal(err)
	}
	attachments, err := db.GetAttachments(ids[0])
	if err != nil || len(attachments) != 1 {
		t.Fatalf("committed attachments=%d err=%v", len(attachments), err)
	}
	data, err := os.ReadFile(filepath.Join(db.AttachmentsPath(), attachments[0].StoragePath))
	if err != nil || string(data) != "payload" {
		t.Fatalf("committed attachment=%q err=%v", data, err)
	}
}

func TestInboundBounceAndMessageRollbackTogether(t *testing.T) {
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
	message := &Message{AccountID: accountID, MessageID: "bounce-atomic", Direction: "inbound", RawMessage: []byte("From: sender@remote.test\r\n\r\nbody\r\n"), ReceivedAt: time.Now()}
	bounces := []InboundVERPBounce{{OriginalRecipient: "first@remote.test", SenderEmail: "alice@example.test", BounceAddress: "first+verp@example.test"}, {OriginalRecipient: "second@remote.test", SenderEmail: "alice@example.test", BounceAddress: "second+verp@example.test"}}
	if _, err := db.Exec(`CREATE TRIGGER fail_second_bounce BEFORE INSERT ON verp_bounces WHEN NEW.original_recipient='second@remote.test' BEGIN SELECT RAISE(FAIL, 'bounce unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveInboundDelivery([]*Message{message}, nil, nil, bounces); err == nil {
		t.Fatal("transaction committed despite second bounce failure")
	}
	var messages, recorded int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE message_id='bounce-atomic'`).Scan(&messages); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM verp_bounces WHERE sender_email='alice@example.test'`).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if messages != 0 || recorded != 0 {
		t.Fatalf("partial transaction: messages=%d bounces=%d", messages, recorded)
	}
}
