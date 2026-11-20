package store

import (
	"testing"
	"time"
)

func TestQueueRetentionOnlyDeletesOldTerminalEntries(t *testing.T) {
	db := mailboxDB(t)
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		t.Fatal(err)
	}
	if days, err := db.QueueRetentionDays(); err != nil || days != 0 {
		t.Fatalf("default: %d %v", days, err)
	}
	if err := db.SetQueueRetentionDays(30); err != nil {
		t.Fatal(err)
	}
	if days, err := db.QueueRetentionDays(); err != nil || days != 30 {
		t.Fatalf("saved: %d %v", days, err)
	}
	ids := map[string]int64{}
	for _, status := range []string{"sent", "failed", "cancelled", "pending", "sending", "uncertain"} {
		id := queueAdminEntry(t, db, status, "a@example.com", "b@example.net")
		ids[status] = id
		if status == "failed" {
			if err := db.MarkDSNSent(id); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.Exec(`UPDATE outbound_queue SET updated_at = ? WHERE id = ?`, databaseTime(time.Now().Add(-40*24*time.Hour)), id); err != nil {
			t.Fatal(err)
		}
		if err := appendQueueEvent(db, id, "fixture", 1, 0, ""); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := db.PruneCompletedQueueEntries(30, time.Now(), 500)
	if err != nil || removed != 3 {
		t.Fatalf("removed=%d err=%v", removed, err)
	}
	for status, id := range ids {
		current, err := db.QueueEntryStatus(id)
		if err != nil {
			t.Fatal(err)
		}
		if status == "sent" || status == "failed" || status == "cancelled" {
			if current != "" {
				t.Fatalf("kept terminal %s", status)
			}
			continue
		}
		if current != status {
			t.Fatalf("removed active %s", status)
		}
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM outbound_queue_events`).Scan(&count); err != nil || count != 3 {
		t.Fatalf("events=%d err=%v", count, err)
	}
}

func TestQueueRetentionPreservesIssuedVERPAddress(t *testing.T) {
	db := mailboxDB(t)
	issued, err := db.EncodeVERP("a@example.com", "bounce+tag@north-west.example.net")
	if err != nil {
		t.Fatal(err)
	}
	id := queueAdminEntry(t, db, "sent", "a@example.com", "bounce+tag@north-west.example.net")
	if _, err := db.Exec(`UPDATE outbound_queue SET verp_bounce_address = ?, updated_at = ? WHERE id = ?`, issued, databaseTime(time.Now().Add(-40*24*time.Hour)), id); err != nil {
		t.Fatal(err)
	}
	if record, err := db.LookupIssuedVERP(issued); err != nil || record == nil || record.Recipient != "bounce+tag@north-west.example.net" {
		t.Fatalf("live queue lookup = %+v, %v", record, err)
	}
	if removed, err := db.PruneCompletedQueueEntries(30, time.Now(), 500); err != nil || removed != 1 {
		t.Fatalf("prune removed %d: %v", removed, err)
	}
	if record, err := db.LookupIssuedVERP(issued); err != nil || record == nil || record.Recipient != "bounce+tag@north-west.example.net" || record.Sender != "a@example.com" {
		t.Fatalf("archived lookup = %+v, %v", record, err)
	}
	if record, err := db.LookupIssuedVERP("a@example.com"); err != nil || record != nil {
		t.Fatalf("ordinary sender accepted as VERP: %+v, %v", record, err)
	}
	lookalike := "a+v1-Ym9ndXNAZXhhbXBsZS5uZXQ@example.com"
	if record, err := db.LookupIssuedVERP(lookalike); err != nil || record != nil {
		t.Fatalf("unissued lookalike accepted: %+v, %v", record, err)
	}
}

func TestArchivedVERPRetentionIsIndependentAndBounded(t *testing.T) {
	db := mailboxDB(t)
	if days, err := db.VERPRetentionDays(); err != nil || days != 0 {
		t.Fatalf("default VERP retention: %d, %v", days, err)
	}
	if err := db.SetQueueRetentionDays(30); err != nil {
		t.Fatal(err)
	}
	if err := db.SetVERPRetentionDays(90); err != nil {
		t.Fatal(err)
	}
	if days, err := db.QueueRetentionDays(); err != nil || days != 30 {
		t.Fatalf("queue retention overwritten: %d, %v", days, err)
	}
	if days, err := db.VERPRetentionDays(); err != nil || days != 90 {
		t.Fatalf("VERP retention not saved: %d, %v", days, err)
	}
	if err := db.SetVERPRetentionDays(-1); err == nil {
		t.Fatal("negative retention accepted")
	}
	now := time.Now().UTC()
	old := databaseTime(now.Add(-100 * 24 * time.Hour))
	for _, address := range []string{"old-a@example.com", "old-b@example.com", "new@example.com", "active@example.com"} {
		if _, err := db.Exec(`INSERT INTO issued_verp(address,recipient,sender,archived_at) VALUES(?,?,?,?)`, address, "recipient@example.net", "sender@example.com", old); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`UPDATE issued_verp SET archived_at = ? WHERE address = ?`, databaseTime(now), "new@example.com"); err != nil {
		t.Fatal(err)
	}
	activeID := queueAdminEntry(t, db, "sent", "sender@example.com", "recipient@example.net")
	if _, err := db.Exec(`UPDATE outbound_queue SET verp_bounce_address = ? WHERE id = ?`, "active@example.com", activeID); err != nil {
		t.Fatal(err)
	}
	removed, err := db.PruneIssuedVERP(90, now, 1)
	if err != nil || removed != 1 {
		t.Fatalf("first bounded batch: %d, %v", removed, err)
	}
	removed, err = db.PruneIssuedVERP(90, now, 500)
	if err != nil || removed != 1 {
		t.Fatalf("second batch: %d, %v", removed, err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM issued_verp`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("retained mappings: %d, %v", count, err)
	}
	if _, err := db.Exec(`UPDATE outbound_queue SET status = 'cancelled' WHERE id = ?`, activeID); err != nil {
		t.Fatal(err)
	}
	removed, err = db.PruneIssuedVERP(90, now, 500)
	if err != nil || removed != 1 {
		t.Fatalf("cancelled mapping: %d, %v", removed, err)
	}
}

func TestQueueRetentionKeepsQueueEntryWhenVERPArchiveFails(t *testing.T) {
	db := mailboxDB(t)
	issued, err := db.EncodeVERP("a@example.com", "bounce@example.net")
	if err != nil {
		t.Fatal(err)
	}
	id := queueAdminEntry(t, db, "sent", "a@example.com", "bounce@example.net")
	if _, err := db.Exec(`UPDATE outbound_queue SET verp_bounce_address = ?, updated_at = ? WHERE id = ?`, issued, databaseTime(time.Now().Add(-40*24*time.Hour)), id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE issued_verp`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PruneCompletedQueueEntries(30, time.Now(), 500); err == nil {
		t.Fatal("expected archive failure")
	}
	if status, err := db.QueueEntryStatus(id); err != nil || status != "sent" {
		t.Fatalf("queue entry was lost after archive failure: %q, %v", status, err)
	}
}

func TestQueueRetentionPreservesPendingFinalDSN(t *testing.T) {
	db := mailboxDB(t)
	id := queueAdminEntry(t, db, "failed", "a@example.com", "b@example.net")
	if _, err := db.Exec(`UPDATE outbound_queue SET dsn_notify = 'FAILURE', updated_at = ? WHERE id = ?`, databaseTime(time.Now().Add(-40*24*time.Hour)), id); err != nil {
		t.Fatal(err)
	}
	if removed, err := db.PruneCompletedQueueEntries(30, time.Now(), 500); err != nil || removed != 0 {
		t.Fatalf("pending final DSN pruned: removed=%d err=%v", removed, err)
	}
	if err := db.MarkDSNSent(id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE outbound_queue SET updated_at = ? WHERE id = ?`, databaseTime(time.Now().Add(-40*24*time.Hour)), id); err != nil {
		t.Fatal(err)
	}
	if removed, err := db.PruneCompletedQueueEntries(30, time.Now(), 500); err != nil || removed != 1 {
		t.Fatalf("completed final DSN not pruned: removed=%d err=%v", removed, err)
	}
}

func TestQueueRetentionPreservesDefaultFailureDSN(t *testing.T) {
	db := mailboxDB(t)
	id := queueAdminEntry(t, db, "failed", "a@example.com", "b@example.net")
	old := databaseTime(time.Now().Add(-40 * 24 * time.Hour))
	if _, err := db.Exec(`UPDATE outbound_queue SET dsn_notify = '', updated_at = ? WHERE id = ?`, old, id); err != nil {
		t.Fatal(err)
	}
	if removed, err := db.PruneCompletedQueueEntries(30, time.Now(), 500); err != nil || removed != 0 {
		t.Fatalf("default failure notice lost: removed=%d err=%v", removed, err)
	}
	if status, err := db.QueueEntryStatus(id); err != nil || status != "failed" {
		t.Fatalf("pending failure notice entry: %q, %v", status, err)
	}
	if err := db.MarkDSNSent(id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE outbound_queue SET updated_at = ? WHERE id = ?`, old, id); err != nil {
		t.Fatal(err)
	}
	if removed, err := db.PruneCompletedQueueEntries(30, time.Now(), 500); err != nil || removed != 1 {
		t.Fatalf("completed default notice retained: removed=%d err=%v", removed, err)
	}
}

func TestQueueRetentionPrunesNullSenderFailure(t *testing.T) {
	db := mailboxDB(t)
	id := queueAdminEntry(t, db, "failed", "a@example.com", "b@example.net")
	old := databaseTime(time.Now().Add(-40 * 24 * time.Hour))
	if _, err := db.Exec(`UPDATE outbound_queue SET mail_from = '', dsn_notify = '', updated_at = ? WHERE id = ?`, old, id); err != nil {
		t.Fatal(err)
	}
	if removed, err := db.PruneCompletedQueueEntries(30, time.Now(), 500); err != nil || removed != 1 {
		t.Fatalf("null-sender entry retained without possible DSN: removed=%d err=%v", removed, err)
	}
}

func TestAdminCancelledDeliveryKeepsFailureNoticeDue(t *testing.T) {
	db := mailboxDB(t)
	id := queueAdminEntry(t, db, "pending", "user1@drafts.example", "remote@example.net")
	if changed, err := db.CancelQueueEntry(id); err != nil || !changed {
		t.Fatalf("cancel: changed=%v err=%v", changed, err)
	}
	old := databaseTime(time.Now().Add(-40 * 24 * time.Hour))
	if _, err := db.Exec(`UPDATE outbound_queue SET updated_at = ? WHERE id = ?`, old, id); err != nil {
		t.Fatal(err)
	}
	entries, err := db.GetPendingFinalDSNs(10)
	if err != nil || len(entries) != 1 || entries[0].ID != id || entries[0].Status != "cancelled" {
		t.Fatalf("cancelled delivery notice: entries=%+v err=%v", entries, err)
	}
	if removed, err := db.PruneCompletedQueueEntries(30, time.Now(), 500); err != nil || removed != 0 {
		t.Fatalf("cancelled delivery lost before notice: removed=%d err=%v", removed, err)
	}
	if err := db.MarkDSNSent(id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE outbound_queue SET updated_at = ? WHERE id = ?`, old, id); err != nil {
		t.Fatal(err)
	}
	if removed, err := db.PruneCompletedQueueEntries(30, time.Now(), 500); err != nil || removed != 1 {
		t.Fatalf("notified cancellation not pruned: removed=%d err=%v", removed, err)
	}
}
