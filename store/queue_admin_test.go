package store

import (
	"testing"
	"time"
)

func queueAdminEntry(t *testing.T, db *DB, status, from, to string) int64 {
	t.Helper()
	id, err := db.EnqueueMessage(&QueueEntry{
		MailFrom: from, RcptTo: to, RawMessage: []byte("message"),
		MaxAttempts: 6, NextRetry: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		if _, err := db.Exec(`UPDATE outbound_queue SET status = ?, attempts = 3, last_error = 'delivery failed' WHERE id = ?`, status, id); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func TestQueueAdminListingDoesNotExposeRawMessage(t *testing.T) {
	db := mailboxDB(t)
	queueAdminEntry(t, db, "failed", "Sender@Example.com", "recipient@example.net")
	page, err := db.ListQueueAdmin("failed", "sender@", 1)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Entries) != 1 || page.StatusCount["failed"] != 1 {
		t.Fatalf("unexpected queue page: %+v", page)
	}
	if page.Entries[0].LastError != "delivery failed" {
		t.Fatalf("missing delivery result: %+v", page.Entries[0])
	}
}

func TestQueueAdminTransitionsAreCompareAndSet(t *testing.T) {
	db := mailboxDB(t)
	failed := queueAdminEntry(t, db, "failed", "a@example.com", "b@example.net")
	changed, err := db.RetryQueueEntry(failed)
	if err != nil || !changed {
		t.Fatalf("retry failed: changed=%v err=%v", changed, err)
	}
	if changed, err = db.RetryQueueEntry(failed); err != nil || changed {
		t.Fatalf("second retry should be a safe miss: changed=%v err=%v", changed, err)
	}
	status, _ := db.QueueEntryStatus(failed)
	if status != "pending" {
		t.Fatalf("retry status = %q", status)
	}
	if changed, err = db.CancelQueueEntry(failed); err != nil || !changed {
		t.Fatalf("cancel failed: changed=%v err=%v", changed, err)
	}
	status, _ = db.QueueEntryStatus(failed)
	if status != "cancelled" {
		t.Fatalf("cancel status = %q", status)
	}
}

func TestQueueAdminCannotCancelActiveDeliveryAndRecoversOnlyStale(t *testing.T) {
	db := mailboxDB(t)
	id := queueAdminEntry(t, db, "sending", "a@example.com", "b@example.net")
	if changed, err := db.CancelQueueEntry(id); err != nil || changed {
		t.Fatalf("active delivery cancellation accepted: changed=%v err=%v", changed, err)
	}
	if changed, err := db.RecoverStaleQueueEntry(id); err != nil || changed {
		t.Fatalf("fresh claim recovered: changed=%v err=%v", changed, err)
	}
	if _, err := db.Exec(`UPDATE outbound_queue SET updated_at = ? WHERE id = ?`, databaseTime(time.Now().Add(-time.Hour)), id); err != nil {
		t.Fatal(err)
	}
	if changed, err := db.RecoverStaleQueueEntry(id); err != nil || !changed {
		t.Fatalf("stale claim not recovered: changed=%v err=%v", changed, err)
	}
	if status, err := db.QueueEntryStatus(id); err != nil || status != "uncertain" {
		t.Fatalf("recovered message was not quarantined: %q %v", status, err)
	}
	if pending, err := db.GetPendingQueue(10); err != nil || len(pending) != 0 {
		t.Fatalf("uncertain message was available for automatic delivery: %d %v", len(pending), err)
	}
}

func TestQueueClaimHeartbeatAndFencing(t *testing.T) {
	db := mailboxDB(t)
	id := queueAdminEntry(t, db, "pending", "a@example.com", "b@example.net")
	token, claimed, err := db.ClaimQueueEntry(id)
	if err != nil || !claimed || token == "" {
		t.Fatalf("claim: %q %v %v", token, claimed, err)
	}
	if _, claimed, err := db.ClaimQueueEntry(id); err != nil || claimed {
		t.Fatalf("double claim: %v %v", claimed, err)
	}
	if _, err := db.Exec(`UPDATE outbound_queue SET updated_at = ? WHERE id = ?`, databaseTime(time.Now().Add(-time.Hour)), id); err != nil {
		t.Fatal(err)
	}
	if alive, err := db.HeartbeatQueueClaim(id, token); err != nil || !alive {
		t.Fatalf("heartbeat: %v %v", alive, err)
	}
	if recovered, err := db.RecoverStaleQueueEntry(id); err != nil || recovered {
		t.Fatalf("recovered active claim: %v %v", recovered, err)
	}
	if err := db.TransitionOwnedQueueEntry(id, "wrong-token", "sent", 1, time.Now(), ""); err == nil {
		t.Fatal("wrong owner finalized delivery")
	}
	if _, err := db.Exec(`UPDATE outbound_queue SET updated_at = ? WHERE id = ?`, databaseTime(time.Now().Add(-time.Hour)), id); err != nil {
		t.Fatal(err)
	}
	if recovered, err := db.RecoverStaleQueueEntry(id); err != nil || !recovered {
		t.Fatalf("stale recovery: %v %v", recovered, err)
	}
	if err := db.TransitionOwnedQueueEntry(id, token, "sent", 1, time.Now(), ""); err != nil {
		t.Fatalf("original worker could not report known outcome: %v", err)
	}
	if resolved, err := db.ResolveUncertainQueueEntry(id, "retry"); err != nil || resolved {
		t.Fatalf("resolved delivery requeued: %v %v", resolved, err)
	}
	id = queueAdminEntry(t, db, "pending", "a@example.com", "c@example.net")
	token, claimed, err = db.ClaimQueueEntry(id)
	if err != nil || !claimed {
		t.Fatalf("second claim: %v %v", claimed, err)
	}
	if _, err := db.Exec(`UPDATE outbound_queue SET updated_at = ? WHERE id = ?`, databaseTime(time.Now().Add(-time.Hour)), id); err != nil {
		t.Fatal(err)
	}
	if recovered, err := db.RecoverStaleQueueEntry(id); err != nil || !recovered {
		t.Fatalf("second stale recovery: %v %v", recovered, err)
	}
	if resolved, err := db.ResolveUncertainQueueEntry(id, "retry"); err != nil || !resolved {
		t.Fatalf("operator could not retry uncertain delivery: %v %v", resolved, err)
	}
	newToken, claimed, err := db.ClaimQueueEntry(id)
	if err != nil || !claimed || newToken == token {
		t.Fatalf("new claim: %q %v %v", newToken, claimed, err)
	}
	if err := db.TransitionOwnedQueueEntry(id, token, "sent", 1, time.Now(), ""); err == nil {
		t.Fatal("stale owner finalized newer claim")
	}
	if err := db.TransitionOwnedQueueEntry(id, newToken, "sent", 1, time.Now(), ""); err != nil {
		t.Fatal(err)
	}
}

func TestStartupRecoveryQuarantinesUnknownOutcome(t *testing.T) {
	db := mailboxDB(t)
	id := queueAdminEntry(t, db, "sending", "a@example.com", "b@example.net")
	if _, err := db.Exec(`UPDATE outbound_queue SET updated_at = ? WHERE id = ?`, databaseTime(time.Now().Add(-time.Hour)), id); err != nil {
		t.Fatal(err)
	}
	if count, err := db.RecoverStaleQueueEntries(); err != nil || count != 1 {
		t.Fatalf("startup recovery: %d %v", count, err)
	}
	if status, err := db.QueueEntryStatus(id); err != nil || status != "uncertain" {
		t.Fatalf("startup recovery status: %s %v", status, err)
	}
	if pending, err := db.GetPendingQueue(10); err != nil || len(pending) != 0 {
		t.Fatalf("unknown outcome was automatically requeued: %d %v", len(pending), err)
	}
}

func TestQueueEventsPreserveObservedOutcomeAndAdminDecision(t *testing.T) {
	db := mailboxDB(t)
	id := queueAdminEntry(t, db, "pending", "a@example.com", "b@example.net")
	token, claimed, err := db.ClaimQueueEntry(id)
	if err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	if err := db.TransitionOwnedQueueEntryWithCode(id, token, "pending", 1, time.Now(), "remote: 450 mailbox busy", 450, ""); err != nil {
		t.Fatal(err)
	}
	events, err := db.ListQueueEvents(id, 50)
	if err != nil || len(events) != 2 {
		t.Fatalf("history: %+v %v", events, err)
	}
	if events[0].Type != "temporary_failure" || events[0].SMTPCode != 450 || events[0].Attempt != 1 || events[1].Type != "attempt_started" {
		t.Fatalf("unexpected history: %+v", events)
	}
	if changed, err := db.CancelQueueEntry(id); err != nil || !changed {
		t.Fatalf("cancel: %v %v", changed, err)
	}
	events, err = db.ListQueueEvents(id, 50)
	if err != nil || len(events) != 3 || events[0].Type != "admin_cancel" {
		t.Fatalf("admin history: %+v %v", events, err)
	}
}
