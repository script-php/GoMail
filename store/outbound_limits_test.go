package store

import (
	"errors"
	"testing"
	"time"

	"gomail/config"
)

func TestOutboundLimitsPersistAndSuspendAtomically(t *testing.T) {
	db := mailboxDB(t)
	db.ConfigureOutboundLimits(config.OutboundLimitsConfig{Enabled: true, MessagesPerHour: 1, MessagesPerDay: 5, RecipientsPerHour: 2, RecipientsPerDay: 10, MaxRecipientsPerMessage: 2, SuspensionMinutes: 30})
	message := func(id string) *Message {
		return &Message{AccountID: 1, MessageID: id, Direction: "outbound", RawMessage: []byte("mail"), ReceivedAt: time.Now()}
	}
	entry := func(recipient string) *QueueEntry {
		return &QueueEntry{MailFrom: "user1@drafts.example", RcptTo: recipient, RawMessage: []byte("mail"), NextRetry: time.Now()}
	}
	if _, err := db.SaveQueuedMessage(message("first"), []*QueueEntry{entry("one@example.net")}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveQueuedMessage(message("second"), []*QueueEntry{entry("two@example.net")}); !errors.Is(err, ErrOutboundLimit) {
		t.Fatalf("second message was not limited: %v", err)
	}
	var messages, queued int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE account_id=1 AND direction='outbound'`).Scan(&messages); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM outbound_queue`).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if messages != 1 || queued != 1 {
		t.Fatalf("rejected attempt was partially queued: messages=%d queue=%d", messages, queued)
	}
	usage, err := db.ListOutboundAccountUsage(time.Now())
	if err != nil || len(usage) != 2 || !usage[0].IsSuspended {
		t.Fatalf("usage=%#v err=%v", usage, err)
	}
	if err := db.ResetOutboundAccountUsage(1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveQueuedMessage(message("after-reset"), []*QueueEntry{entry("three@example.net")}); err != nil {
		t.Fatalf("reset did not unlock account: %v", err)
	}
}

func TestOutboundMaximumRecipientsDoesNotQueue(t *testing.T) {
	db := mailboxDB(t)
	db.ConfigureOutboundLimits(config.OutboundLimitsConfig{Enabled: true, MessagesPerHour: 10, MessagesPerDay: 20, RecipientsPerHour: 20, RecipientsPerDay: 40, MaxRecipientsPerMessage: 1, SuspensionMinutes: 30})
	entries := []*QueueEntry{{RcptTo: "one@example.net", RawMessage: []byte("mail")}, {RcptTo: "two@example.net", RawMessage: []byte("mail")}}
	if _, err := db.SaveQueuedMessage(&Message{AccountID: 1, MessageID: "too-many", Direction: "outbound", ReceivedAt: time.Now()}, entries); !errors.Is(err, ErrOutboundLimit) {
		t.Fatalf("recipient limit error=%v", err)
	}
	var queued int
	_ = db.QueryRow(`SELECT COUNT(*) FROM outbound_queue`).Scan(&queued)
	if queued != 0 {
		t.Fatalf("queued %d recipients after rejection", queued)
	}
}

func TestManualSuspensionAppliesWhenAutomaticLimitsDisabled(t *testing.T) {
	db := mailboxDB(t)
	db.ConfigureOutboundLimits(config.OutboundLimitsConfig{})
	until := time.Now().Add(time.Hour)
	if err := db.SetOutboundAccountSuspension(1, &until); err != nil {
		t.Fatal(err)
	}
	_, err := db.SaveQueuedMessage(&Message{AccountID: 1, MessageID: "manual-suspend", Direction: "outbound", ReceivedAt: time.Now()}, []*QueueEntry{{RcptTo: "one@example.net", RawMessage: []byte("mail")}})
	if !errors.Is(err, ErrOutboundLimit) {
		t.Fatalf("manual suspension was not enforced: %v", err)
	}
}
