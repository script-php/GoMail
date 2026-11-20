package parser

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gomail/store"
)

func repairFixture(t *testing.T) (*store.DB, *store.Message) {
	t.Helper()
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	domainID, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "user@example.test", PasswordHash: "hash", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.Join([]string{
		"From: sender@example.test", "To: user@example.test", "Subject: attachment",
		"MIME-Version: 1.0", "Content-Type: multipart/mixed; boundary=parts", "",
		"--parts", "Content-Type: text/plain", "", "body",
		"--parts", "Content-Type: text/plain; name=note.txt",
		"Content-Disposition: attachment; filename=note.txt", "Content-Transfer-Encoding: base64", "",
		"aGVsbG8gYXR0YWNobWVudA==", "--parts--", "",
	}, "\r\n")
	msg := &store.Message{AccountID: accountID, MessageID: "<attachment@example.test>", Direction: "inbound", MailFrom: "sender@example.test", RcptTo: "user@example.test", FromAddr: "sender@example.test", ToAddr: "user@example.test", RawMessage: []byte(raw), HasAttachments: true, ReceivedAt: time.Now()}
	msg.ID, err = db.SaveMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	return db, msg
}

func TestRepairAttachmentsReconstructsAndIsIdempotent(t *testing.T) {
	db, msg := repairFixture(t)
	for i := 0; i < 2; i++ {
		if err := RepairAttachments(db, msg, db.AttachmentsPath()); err != nil {
			t.Fatal(err)
		}
	}
	attachments, err := db.GetAttachments(msg.ID)
	if err != nil || len(attachments) != 1 {
		t.Fatalf("repaired metadata: %d attachments, %v", len(attachments), err)
	}
	data, err := os.ReadFile(filepath.Join(db.AttachmentsPath(), attachments[0].StoragePath))
	if err != nil || string(data) != "hello attachment" {
		t.Fatalf("repaired bytes: %q, %v", data, err)
	}
}

func TestRepairAttachmentsRetriesAfterDiskFailure(t *testing.T) {
	db, msg := repairFixture(t)
	if err := RepairAttachments(db, msg, filepath.Join(db.AttachmentsPath(), "missing-directory")); err == nil {
		t.Fatal("expected sidecar disk failure")
	}
	attachments, err := db.GetAttachments(msg.ID)
	if err != nil || len(attachments) != 0 {
		t.Fatalf("failed repair left metadata: %d, %v", len(attachments), err)
	}
	stored, err := db.GetMessage(msg.ID, msg.AccountID)
	if err != nil || stored == nil || !stored.HasAttachments {
		t.Fatalf("attachment repair signal lost: %+v, %v", stored, err)
	}
	if err := RepairAttachments(db, msg, db.AttachmentsPath()); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestRepairAttachmentsRetriesAfterMetadataFailure(t *testing.T) {
	db, msg := repairFixture(t)
	if _, err := db.Exec(`CREATE TRIGGER reject_repair BEFORE INSERT ON attachments BEGIN SELECT RAISE(FAIL, 'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := RepairAttachments(db, msg, db.AttachmentsPath()); err == nil {
		t.Fatal("expected metadata failure")
	}
	attachments, err := db.GetAttachments(msg.ID)
	if err != nil || len(attachments) != 0 {
		t.Fatalf("failed repair left metadata: %d, %v", len(attachments), err)
	}
	files, err := os.ReadDir(db.AttachmentsPath())
	if err != nil || len(files) != 0 {
		t.Fatalf("failed repair left files: %d, %v", len(files), err)
	}
	if _, err := db.Exec(`DROP TRIGGER reject_repair`); err != nil {
		t.Fatal(err)
	}
	if err := RepairAttachments(db, msg, db.AttachmentsPath()); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestRepairAttachmentsIgnoresOrphanFromInterruptedCommit(t *testing.T) {
	db, msg := repairFixture(t)
	data := []byte("hello attachment")
	hash := sha256.Sum256(data)
	// This is the name used before sidecars gained a random suffix. It can
	// remain on disk if a process dies after the write but before DB commit.
	orphan := filepath.Join(db.AttachmentsPath(), fmt.Sprintf("%d_0_%x.txt", msg.ID, hash[:8]))
	if err := os.WriteFile(orphan, []byte("stale, untrusted data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RepairAttachments(db, msg, db.AttachmentsPath()); err != nil {
		t.Fatalf("repair blocked by orphan: %v", err)
	}
	attachments, err := db.GetAttachments(msg.ID)
	if err != nil || len(attachments) != 1 {
		t.Fatalf("repaired metadata: %d attachments, %v", len(attachments), err)
	}
	if attachments[0].StoragePath == filepath.Base(orphan) {
		t.Fatal("repair reused untrusted orphan")
	}
	stored, err := os.ReadFile(filepath.Join(db.AttachmentsPath(), attachments[0].StoragePath))
	if err != nil || string(stored) != string(data) {
		t.Fatalf("repaired bytes: %q, %v", stored, err)
	}
}

func TestRepairAttachmentsRebuildsMissingSidecar(t *testing.T) {
	db, msg := repairFixture(t)
	if err := RepairAttachments(db, msg, db.AttachmentsPath()); err != nil {
		t.Fatal(err)
	}
	before, err := db.GetAttachments(msg.ID)
	if err != nil || len(before) != 1 {
		t.Fatalf("initial attachments: %d, %v", len(before), err)
	}
	if err := os.Remove(filepath.Join(db.AttachmentsPath(), before[0].StoragePath)); err != nil {
		t.Fatal(err)
	}
	if err := RepairAttachments(db, msg, db.AttachmentsPath()); err != nil {
		t.Fatalf("repair missing sidecar: %v", err)
	}
	after, err := db.GetAttachments(msg.ID)
	if err != nil || len(after) != 1 || after[0].StoragePath == before[0].StoragePath {
		t.Fatalf("sidecar was not rebuilt: %+v, %v", after, err)
	}
	data, err := os.ReadFile(filepath.Join(db.AttachmentsPath(), after[0].StoragePath))
	if err != nil || string(data) != "hello attachment" {
		t.Fatalf("rebuilt bytes: %q, %v", data, err)
	}
}

func TestRepairAttachmentsKeepsMetadataWhenRebuildFails(t *testing.T) {
	db, msg := repairFixture(t)
	if _, err := db.Exec(`INSERT INTO attachments (message_id, filename, content_type, size, storage_path) VALUES (?, ?, ?, ?, ?)`, msg.ID, "note.txt", "text/plain", 16, "missing.txt"); err != nil {
		t.Fatal(err)
	}
	if err := RepairAttachments(db, msg, filepath.Join(db.AttachmentsPath(), "missing-directory")); err == nil {
		t.Fatal("expected sidecar write failure")
	}
	attachments, err := db.GetAttachments(msg.ID)
	if err != nil || len(attachments) != 1 || attachments[0].StoragePath != "missing.txt" {
		t.Fatalf("failed rebuild changed metadata: %+v, %v", attachments, err)
	}
}

func TestRepairAttachmentsRebuildsPartialMetadata(t *testing.T) {
	db, msg := repairFixture(t)
	second := strings.Join([]string{
		"--parts", "Content-Type: text/plain; name=second.txt",
		"Content-Disposition: attachment; filename=second.txt", "", "second", "",
	}, "\r\n")
	msg.RawMessage = []byte(strings.Replace(string(msg.RawMessage), "--parts--", second+"--parts--", 1))
	if _, err := db.Exec(`UPDATE messages SET raw_message = ? WHERE id = ?`, msg.RawMessage, msg.ID); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(db.AttachmentsPath(), "first.txt"), []byte("hello attachment"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO attachments (message_id, filename, content_type, size, storage_path) VALUES (?, ?, ?, ?, ?)`, msg.ID, "note.txt", "text/plain", 16, "first.txt"); err != nil {
		t.Fatal(err)
	}
	if err := RepairAttachments(db, msg, db.AttachmentsPath()); err != nil {
		t.Fatalf("repair partial metadata: %v", err)
	}
	attachments, err := db.GetAttachments(msg.ID)
	if err != nil || len(attachments) != 2 {
		t.Fatalf("partial metadata remained: %d, %v", len(attachments), err)
	}
}

func TestRepairAttachmentsRejectsWrongAccount(t *testing.T) {
	db, msg := repairFixture(t)
	msg.AccountID++
	if err := RepairAttachments(db, msg, db.AttachmentsPath()); err == nil {
		t.Fatal("wrong-account repair unexpectedly succeeded")
	}
	attachments, err := db.GetAttachments(msg.ID)
	if err != nil || len(attachments) != 0 {
		t.Fatalf("wrong-account repair changed metadata: %d, %v", len(attachments), err)
	}
}
