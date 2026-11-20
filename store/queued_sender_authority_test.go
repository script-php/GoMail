package store

import (
	"errors"
	"testing"
	"time"
)

func TestQueuedSubmissionRechecksSenderBeforeCommit(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change string
	}{
		{"disabled account", `UPDATE accounts SET is_active = 0 WHERE id = 1`},
		{"disabled domain", `UPDATE domains SET is_active = 0 WHERE id = 1`},
		{"deleted account", `DELETE FROM accounts WHERE id = 1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := mailboxDB(t)
			if _, err := db.Exec(tc.change); err != nil {
				t.Fatal(err)
			}
			message := &Message{AccountID: 1, MailFrom: "user1@drafts.example", Direction: "outbound", MessageID: tc.name, ReceivedAt: time.Now()}
			entry := &QueueEntry{MailFrom: message.MailFrom, RcptTo: "recipient@example.net", RawMessage: []byte("Subject: test\r\n\r\nbody\r\n")}
			if _, err := db.SaveQueuedMessage(message, []*QueueEntry{entry}); !errors.Is(err, ErrSenderUnavailable) {
				t.Fatalf("SaveQueuedMessage error = %v, want unavailable sender", err)
			}
			var messages, queued int
			if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE account_id = 1`).Scan(&messages); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM outbound_queue WHERE origin_account_id = 1`).Scan(&queued); err != nil {
				t.Fatal(err)
			}
			if messages != 0 || queued != 0 {
				t.Fatalf("rejected submission left %d messages and %d queue entries", messages, queued)
			}
		})
	}
}
