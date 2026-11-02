package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestQueueSenderAllowedLifecycle(t *testing.T) {
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
	result, err := db.Exec(`INSERT INTO accounts(domain_id,email,password_hash) VALUES(?,?,?)`, domainID, "alice@example.test", "unused")
	if err != nil {
		t.Fatal(err)
	}
	accountID, _ := result.LastInsertId()
	entry := &QueueEntry{OriginAccountID: accountID, MailFrom: "alice@example.test"}
	queueID, err := db.EnqueueMessage(&QueueEntry{OriginAccountID: accountID, MailFrom: entry.MailFrom, RcptTo: "bob@remote.test", RawMessage: []byte("test"), MaxAttempts: 1, NextRetry: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	check := func(want bool) {
		t.Helper()
		allowed, _, err := db.QueueSenderAllowed(entry, time.Now())
		if err != nil || allowed != want {
			t.Fatalf("allowed=%v err=%v want=%v", allowed, err, want)
		}
	}
	check(true)
	if _, err := db.Exec(`UPDATE accounts SET is_active=0 WHERE id=?`, accountID); err != nil {
		t.Fatal(err)
	}
	check(false)
	if _, err := db.Exec(`UPDATE accounts SET is_active=1 WHERE id=?`, accountID); err != nil {
		t.Fatal(err)
	}
	suspendedUntil := time.Now().Add(time.Hour)
	if err := db.SetOutboundAccountSuspension(accountID, &suspendedUntil); err != nil {
		t.Fatal(err)
	}
	check(false)
	if err := db.SetOutboundAccountSuspension(accountID, nil); err != nil {
		t.Fatal(err)
	}
	check(true)
	if _, err := db.Exec(`DELETE FROM accounts WHERE id=?`, accountID); err != nil {
		t.Fatal(err)
	}
	var retainedOrigin int64
	if err := db.QueryRow(`SELECT origin_account_id FROM outbound_queue WHERE id=?`, queueID).Scan(&retainedOrigin); err != nil || retainedOrigin != accountID {
		t.Fatalf("deleted account lost queue provenance: origin=%d err=%v", retainedOrigin, err)
	}
	check(false)
	entry.OriginAccountID = -1
	check(false)
	entry.OriginAccountID = 0
	check(true)
	entry.MailFrom = ""
	check(true) // receiver-generated DSNs have MAIL FROM:<>
	entry.MailFrom = "alice@example.test"
	if _, err := db.Exec(`UPDATE domains SET is_active=0 WHERE id=?`, domainID); err != nil {
		t.Fatal(err)
	}
	check(false)
}
