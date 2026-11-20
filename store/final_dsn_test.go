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
	if _, err := db.SaveFinalDSNMessage(report(), id, "sent"); err == nil {
		t.Fatal("expected mailbox insertion failure")
	}
	var sent int
	if err := db.QueryRow(`SELECT dsn_sent FROM outbound_queue WHERE id = ?`, id).Scan(&sent); err != nil || sent != 0 {
		t.Fatalf("failed report marked DSN sent: %d, %v", sent, err)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_final_dsn`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveFinalDSNMessage(report(), id, "sent"); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if _, err := db.SaveFinalDSNMessage(report(), id, "sent"); !errors.Is(err, ErrDSNAlreadySent) {
		t.Fatalf("duplicate report result: %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE message_id = 'dsn-fixture'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("reports=%d err=%v", count, err)
	}
}

func TestFinalDSNRejectsStaleOutcome(t *testing.T) {
	db := mailboxDB(t)
	id := queueAdminEntry(t, db, "failed", "user1@drafts.example", "remote@example.net")
	inbox, err := db.GetFolderByType(1, "inbox")
	if err != nil {
		t.Fatal(err)
	}
	report := &Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "stale-dsn", Direction: "inbound", ToAddr: "user1@drafts.example", RawMessage: []byte("Subject: DSN\r\n\r\nreport"), ReceivedAt: time.Now()}
	if _, err := db.SaveFinalDSNMessage(report, id, "sent"); !errors.Is(err, ErrDSNStateChanged) {
		t.Fatalf("stale success notice: %v", err)
	}
	var sent, count int
	if err := db.QueryRow(`SELECT dsn_sent FROM outbound_queue WHERE id = ?`, id).Scan(&sent); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE message_id = 'stale-dsn'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if sent != 0 || count != 0 {
		t.Fatalf("stale notice persisted: marker=%d messages=%d", sent, count)
	}
}

func TestDelayDSNMailboxAndMarkerAreAtomic(t *testing.T) {
	db := mailboxDB(t)
	id := queueAdminEntry(t, db, "pending", "user1@drafts.example", "remote@example.net")
	inbox, err := db.GetFolderByType(1, "inbox")
	if err != nil {
		t.Fatal(err)
	}
	report := func() *Message {
		return &Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "delay-dsn-fixture", Direction: "inbound", ToAddr: "user1@drafts.example", RawMessage: []byte("Subject: Delayed\r\n\r\nreport"), ReceivedAt: time.Now()}
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_delay_dsn BEFORE INSERT ON messages BEGIN SELECT RAISE(FAIL, 'mailbox unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveDelayDSNMessage(report(), id); err == nil {
		t.Fatal("expected mailbox insertion failure")
	}
	var sent int
	if err := db.QueryRow(`SELECT dsn_delay_sent FROM outbound_queue WHERE id = ?`, id).Scan(&sent); err != nil || sent != 0 {
		t.Fatalf("failed delayed report marked sent: %d, %v", sent, err)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_delay_dsn`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveDelayDSNMessage(report(), id); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if _, err := db.SaveDelayDSNMessage(report(), id); !errors.Is(err, ErrDSNAlreadySent) {
		t.Fatalf("duplicate report result: %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE message_id = 'delay-dsn-fixture'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("delayed reports=%d err=%v", count, err)
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
