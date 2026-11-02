package store

import (
	"errors"
	"testing"
	"time"
)

func TestFinalDSNMailboxAndMarkerAreAtomic(t *testing.T) {
	db := mailboxDB(t)
	id := queueAdminEntry(t, db, "sent", "user1@drafts.example", "remote@example.net")
	if _, err := db.Exec(`UPDATE outbound_queue SET dsn_notify = 'SUCCESS' WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	inbox, err := db.GetFolderByType(1, "inbox")
	if err != nil {
		t.Fatal(err)
	}
	report := func() *Message {
		return &Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "dsn-fixture", Direction: "inbound", ToAddr: "user1@drafts.example", RawMessage: []byte("Subject: DSN\r\n\r\nreport"), ReceivedAt: time.Now()}
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_final_dsn BEFORE INSERT ON messages BEGIN SELECT RAISE(FAIL, 'mailbox unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveFinalDSNMessage(report(), id); err == nil {
		t.Fatal("expected mailbox insertion failure")
	}
	var sent int
	if err := db.QueryRow(`SELECT dsn_sent FROM outbound_queue WHERE id = ?`, id).Scan(&sent); err != nil || sent != 0 {
		t.Fatalf("failed report marked DSN sent: %d, %v", sent, err)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_final_dsn`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveFinalDSNMessage(report(), id); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if _, err := db.SaveFinalDSNMessage(report(), id); !errors.Is(err, ErrDSNAlreadySent) {
		t.Fatalf("duplicate report result: %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE message_id = 'dsn-fixture'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("reports=%d err=%v", count, err)
	}
}

func TestFinalDSNRetryIncludesSubmissionWithoutNotifyParameter(t *testing.T) {
	db := mailboxDB(t)
	id := queueAdminEntry(t, db, "failed", "user1@drafts.example", "remote@example.net")
	if _, err := db.Exec(`UPDATE outbound_queue SET dsn_notify = '', dsn_retry_at = ? WHERE id = ?`, databaseTime(time.Now().Add(-time.Minute)), id); err != nil {
		t.Fatal(err)
	}
	entries, err := db.GetPendingFinalDSNs(10)
	if err != nil || len(entries) != 1 || entries[0].ID != id {
		t.Fatalf("failure-only default was not retried: entries=%+v err=%v", entries, err)
	}
}
