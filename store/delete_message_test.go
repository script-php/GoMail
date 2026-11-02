package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDeleteMessageRefreshesSourceAndTrashCounts(t *testing.T) {
	root := t.TempDir()
	db, err := Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.com'); INSERT INTO accounts(id,domain_id,email,password_hash) VALUES(1,1,'one@example.com','x')`); err != nil {
		t.Fatal(err)
	}
	if err := db.DefaultFolders(1); err != nil {
		t.Fatal(err)
	}
	inbox, err := db.GetFolderByType(1, "inbox")
	if err != nil || inbox == nil {
		t.Fatalf("inbox = %v, %v", inbox, err)
	}
	id, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "delete-counts", Direction: "inbound", ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateFolderCounts(inbox.ID); err != nil {
		t.Fatal(err)
	}
	before, _ := db.GetIMAPMessageState(1, id)
	if err := db.DeleteMessage(id); err != nil {
		t.Fatal(err)
	}
	inbox, _ = db.GetFolderByType(1, "inbox")
	trash, _ := db.GetFolderByType(1, "trash")
	if inbox.TotalCount != 0 || trash == nil || trash.TotalCount != 1 {
		t.Fatalf("counts after delete: inbox=%d trash=%v; want inbox=0 trash=1", inbox.TotalCount, trash)
	}
	after, _ := db.GetIMAPMessageState(1, id)
	if after == nil || after.FolderID != trash.ID || before == nil {
		t.Fatalf("IMAP state after delete: before=%#v after=%#v", before, after)
	}
}
