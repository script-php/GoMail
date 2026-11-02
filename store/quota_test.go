package store

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestMailboxQuotaReservationAndReclamation(t *testing.T) {
	db := mailboxDB(t)
	if _, err := db.Exec(`UPDATE accounts SET quota_bytes=10 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	inbox, _ := db.GetFolderByType(1, "inbox")
	id, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "fits", Direction: "inbound", Size: 10, ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "over", Direction: "inbound", Size: 1, ReceivedAt: time.Now()}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("over-quota insert returned %v", err)
	}
	used, quota, err := db.MailboxUsage(1)
	if err != nil || used != 10 || quota != 10 {
		t.Fatalf("unexpected usage used=%d quota=%d err=%v", used, quota, err)
	}
	if err := db.ApplyMessageAction(1, []int64{id}, "trash", 0); err != nil {
		t.Fatal(err)
	}
	used, _, _ = db.MailboxUsage(1)
	if used != 10 {
		t.Fatal("moving to Trash incorrectly released quota")
	}
	if err := db.PermanentlyDeleteMessages(1, []int64{id}); err != nil {
		t.Fatal(err)
	}
	used, _, _ = db.MailboxUsage(1)
	if used != 0 {
		t.Fatalf("permanent deletion did not reclaim quota: %d", used)
	}
}

func TestMailboxQuotaConcurrentInsert(t *testing.T) {
	db := mailboxDB(t)
	if _, err := db.Exec(`UPDATE accounts SET quota_bytes=10 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	inbox, _ := db.GetFolderByType(1, "inbox")
	start := make(chan struct{})
	var wg sync.WaitGroup
	var successes int
	var mu sync.Mutex
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "race", Direction: "inbound", Size: 6, ReceivedAt: time.Now()})
			if err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			} else if !errors.Is(err, ErrQuotaExceeded) {
				t.Errorf("unexpected insert error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if successes != 1 {
		t.Fatalf("expected one successful concurrent insert, got %d", successes)
	}
	used, _, _ := db.MailboxUsage(1)
	if used != 6 {
		t.Fatalf("concurrent usage is %d, want 6", used)
	}
}

func TestSaveMessagesQuotaFailureIsAtomic(t *testing.T) {
	db := mailboxDB(t)
	if _, err := db.Exec(`UPDATE accounts SET quota_bytes=10 WHERE id IN (1,2)`); err != nil {
		t.Fatal(err)
	}
	inbox1, _ := db.GetFolderByType(1, "inbox")
	inbox2, _ := db.GetFolderByType(2, "inbox")
	_, err := db.SaveMessages([]*Message{
		{AccountID: 1, FolderID: &inbox1.ID, MessageID: "one", Direction: "inbound", Size: 6, ReceivedAt: time.Now()},
		{AccountID: 2, FolderID: &inbox2.ID, MessageID: "two", Direction: "inbound", Size: 11, ReceivedAt: time.Now()},
	})
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("batch quota failure returned %v", err)
	}
	for _, accountID := range []int64{1, 2} {
		used, _, _ := db.MailboxUsage(accountID)
		if used != 0 {
			t.Fatalf("account %d retained partial quota reservation: %d", accountID, used)
		}
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE account_id=?`, accountID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("account %d received partial batch: count=%d err=%v", accountID, count, err)
		}
	}
}

func TestDraftQuotaUsesSizeDelta(t *testing.T) {
	db := mailboxDB(t)
	if _, err := db.Exec(`UPDATE accounts SET quota_bytes=50 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	id, err := db.SaveDraft(1, 0, "a@b", "c@d", "", "s", "body")
	if err != nil {
		t.Fatal(err)
	}
	used, _, _ := db.MailboxUsage(1)
	if used == 0 {
		t.Fatal("draft did not consume quota")
	}
	if _, err := db.SaveDraft(1, id, "a@b", "c@d", "", "s", "this body is far too large for the remaining quota and must fail"); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("oversized draft update returned %v", err)
	}
	usedAfter, _, _ := db.MailboxUsage(1)
	if usedAfter != used {
		t.Fatalf("failed draft update changed usage from %d to %d", used, usedAfter)
	}
	if err := db.DeleteDraft(1, id); err != nil {
		t.Fatal(err)
	}
	usedAfter, _, _ = db.MailboxUsage(1)
	if usedAfter != 0 {
		t.Fatalf("draft deletion did not reclaim quota: %d", usedAfter)
	}
}
