package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestMailboxReservationRejectsDisabledDomain(t *testing.T) {
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
	accountID, err := db.CreateAccount(&Account{DomainID: domainID, Email: "bob@example.test", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE domains SET is_active=0 WHERE id=?`, domainID); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := reserveMailboxBytes(tx, accountID, 123); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("disabled-domain reservation error=%v, want unavailable mailbox", err)
	}
	var used int64
	if err := tx.QueryRow(`SELECT mailbox_used_bytes FROM accounts WHERE id=?`, accountID).Scan(&used); err != nil || used != 0 {
		t.Fatalf("disabled-domain mailbox usage=%d err=%v", used, err)
	}
}
