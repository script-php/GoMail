package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateAccountRollsBackWhenFolderProvisioningFails(t *testing.T) {
	root := t.TempDir()
	db, err := Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	domainID, err := db.CreateDomain(&Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_folder BEFORE INSERT ON folders BEGIN SELECT RAISE(ABORT, 'folder failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateAccount(&Account{DomainID: domainID, Email: "partial@example.test", PasswordHash: "hash", IsActive: true}); err == nil {
		t.Fatal("account creation succeeded despite folder provisioning failure")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE email='partial@example.test'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("partially provisioned account was committed")
	}
}

func TestDeleteAccountRemovesOwnedAttachmentFiles(t *testing.T) {
	root := t.TempDir()
	attachments := filepath.Join(root, "attachments")
	db, err := Open(filepath.Join(root, "mail.db"), attachments)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	domainID, err := db.CreateDomain(&Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&Account{DomainID: domainID, Email: "delete@example.test", PasswordHash: "hash", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := db.GetFolderByType(accountID, "inbox")
	if err != nil || inbox == nil {
		t.Fatalf("inbox: %v", err)
	}
	messageID, err := db.SaveMessage(&Message{AccountID: accountID, FolderID: &inbox.ID, MessageID: "delete-me", Direction: "inbound", Size: 4, ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	storedPath := filepath.Join("delete", "attachment.bin")
	fullPath := filepath.Join(attachments, storedPath)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO attachments(message_id,filename,content_type,size,storage_path) VALUES(?,?,?,?,?)`, messageID, "attachment.bin", "application/octet-stream", 4, storedPath); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteAccount(accountID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fullPath); !os.IsNotExist(err) {
		t.Fatalf("attachment file survived account deletion: %v", err)
	}
	if account, err := db.GetAccount(accountID); err != nil || account != nil {
		t.Fatalf("account survived deletion: %+v %v", account, err)
	}
}

func TestDeleteDomainRemovesDescendantAttachmentFiles(t *testing.T) {
	root := t.TempDir()
	attachments := filepath.Join(root, "attachments")
	db, err := Open(filepath.Join(root, "mail.db"), attachments)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	domainID, err := db.CreateDomain(&Domain{Domain: "domain-delete.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&Account{DomainID: domainID, Email: "user@domain-delete.test", PasswordHash: "hash", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	messageID, err := db.SaveMessage(&Message{AccountID: accountID, MessageID: "domain-delete", Direction: "inbound", Size: 4, ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	storedPath := filepath.Join("domain-delete", "attachment.bin")
	fullPath := filepath.Join(attachments, storedPath)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO attachments(message_id,filename,content_type,size,storage_path) VALUES(?,?,?,?,?)`, messageID, "attachment.bin", "application/octet-stream", 4, storedPath); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteDomain(domainID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fullPath); !os.IsNotExist(err) {
		t.Fatalf("attachment file survived domain deletion: %v", err)
	}
}
