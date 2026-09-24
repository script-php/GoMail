package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPermanentDeleteRequiresTrashAndRemovesAttachment(t *testing.T) {
	root := t.TempDir()
	db, err := Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.com'); INSERT INTO accounts(id,domain_id,email,password_hash) VALUES(1,1,'one@example.com','x'),(2,1,'two@example.com','x')`); err != nil {
		t.Fatal(err)
	}
	if err := db.DefaultFolders(1); err != nil {
		t.Fatal(err)
	}
	inbox, _ := db.GetFolderByType(1, "inbox")
	id, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "m1", Direction: "inbound", ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(db.AttachmentsPath(), "file.bin")
	if err := os.WriteFile(path, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveAttachment(&Attachment{MessageID: id, Filename: "file.bin", StoragePath: "file.bin"}); err != nil {
		t.Fatal(err)
	}
	if err := db.PermanentlyDeleteMessages(1, []int64{id}); err == nil {
		t.Fatal("message outside Trash was permanently deleted")
	}
	if err := db.ApplyMessageAction(1, []int64{id}, "trash", 0); err != nil {
		t.Fatal(err)
	}
	if err := db.PermanentlyDeleteMessages(2, []int64{id}); err == nil {
		t.Fatal("other account permanently deleted message")
	}
	if err := db.PermanentlyDeleteMessages(1, []int64{id}); err != nil {
		t.Fatal(err)
	}
	if message, _ := db.GetMessage(id, 1); message != nil {
		t.Fatal("message still exists")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("attachment remains: %v", err)
	}
}
