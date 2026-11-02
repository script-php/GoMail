package store

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestQueuedMDNIsAtomicRetryableAndIdempotent(t *testing.T) {
	db := mailboxDB(t)
	inbox, err := db.GetFolderByType(1, "inbox")
	if err != nil {
		t.Fatal(err)
	}
	sourceID, err := db.SaveMessage(&Message{
		AccountID: 1, FolderID: &inbox.ID, MessageID: "source-mdn",
		Direction: "inbound", FromAddr: "sender@example.net", ToAddr: "user1@drafts.example",
		Subject: "receipt requested", RawMessage: []byte("Subject: receipt requested\r\n\r\nbody"),
		MDNRequested: true, MDNAddress: "sender@example.net", ReceivedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sent, err := db.GetFolderByType(1, "sent")
	if err != nil {
		t.Fatal(err)
	}
	queue := func() error {
		_, err := db.SaveQueuedMDNMessage(&Message{
			AccountID: 1, FolderID: &sent.ID, MessageID: "receipt-copy", Direction: "outbound",
			MailFrom: "user1@drafts.example", FromAddr: "user1@drafts.example", ToAddr: "sender@example.net",
			RawMessage: []byte("Subject: MDN\r\n\r\nreceipt"), ReceivedAt: time.Now(),
		}, []*QueueEntry{{MailFrom: "user1@drafts.example", RcptTo: "sender@example.net", RawMessage: []byte("Subject: MDN\r\n\r\nreceipt"), MaxAttempts: 3, NextRetry: time.Now()}}, sourceID)
		return err
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_mdn_queue BEFORE INSERT ON outbound_queue BEGIN SELECT RAISE(FAIL, 'queue unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := queue(); err == nil {
		t.Fatal("expected transient queue failure")
	}
	var sentFlag, queued int
	if err := db.QueryRow(`SELECT mdn_sent FROM messages WHERE id = ?`, sourceID).Scan(&sentFlag); err != nil || sentFlag != 0 {
		t.Fatalf("failed enqueue marked source: %d, %v", sentFlag, err)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_mdn_queue`); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- queue() }()
	}
	wg.Wait()
	close(results)
	var successes, duplicates int
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrMDNAlreadySent):
			duplicates++
		default:
			t.Fatalf("unexpected concurrent result: %v", err)
		}
	}
	if successes != 1 || duplicates != 1 {
		t.Fatalf("successes=%d duplicates=%d", successes, duplicates)
	}
	if err := db.QueryRow(`SELECT mdn_sent FROM messages WHERE id = ?`, sourceID).Scan(&sentFlag); err != nil || sentFlag != 1 {
		t.Fatalf("source MDN state: %d, %v", sentFlag, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM outbound_queue WHERE rcpt_to = 'sender@example.net'`).Scan(&queued); err != nil || queued != 1 {
		t.Fatalf("queued receipts: %d, %v", queued, err)
	}
}
