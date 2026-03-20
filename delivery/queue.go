package delivery

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"gomail/auth"
	"gomail/config"
	"gomail/store"
)

// Queue manages the outbound message delivery queue.
type Queue struct {
	db     *store.DB
	cfg    *config.Config
	signer *auth.DKIMSigner
}

// NewQueue creates a delivery queue manager.
func NewQueue(db *store.DB, cfg *config.Config, signer *auth.DKIMSigner) *Queue {
	return &Queue{
		db:     db,
		cfg:    cfg,
		signer: signer,
	}
}

// Enqueue adds a new outbound message to the delivery queue.
// It DKIM-signs the message, stores it, and creates queue entries for each recipient.
func (q *Queue) Enqueue(from string, to []string, rawMessage []byte) error {
	// DKIM sign the message
	var signedMessage []byte
	if q.signer != nil {
		var err error
		signedMessage, err = q.signer.Sign(rawMessage)
		if err != nil {
			log.Printf("[delivery] DKIM signing failed: %v (sending unsigned)", err)
			signedMessage = rawMessage
		}
	} else {
		signedMessage = rawMessage
	}

	// Store the outbound message in the messages table
	rcptJSON, _ := json.Marshal(to)

	msg := &store.Message{
		MessageID:  fmt.Sprintf("%d@%s", time.Now().UnixNano(), q.cfg.Server.Domain),
		Direction:  "outbound",
		MailFrom:   from,
		RcptTo:     string(rcptJSON),
		FromAddr:   from,
		ToAddr:     joinAddrs(to),
		RawMessage: signedMessage,
		Size:       int64(len(signedMessage)),
		IsRead:     true, // Outbound messages are already "read"
		ReceivedAt: time.Now(),
	}

	msgID, err := q.db.SaveMessage(msg)
	if err != nil {
		return fmt.Errorf("saving outbound message: %w", err)
	}

	// Create a queue entry for each recipient
	for _, rcpt := range to {
		entry := &store.QueueEntry{
			MessageID:   &msgID,
			MailFrom:    from,
			RcptTo:      rcpt,
			RawMessage:  signedMessage,
			MaxAttempts: q.cfg.Delivery.MaxRetries,
			NextRetry:   time.Now(),
		}

		if _, err := q.db.EnqueueMessage(entry); err != nil {
			log.Printf("[delivery] enqueue error for %s: %v", rcpt, err)
		}
	}

	log.Printf("[delivery] enqueued message from=%s to=%v id=%d", from, to, msgID)
	return nil
}

func joinAddrs(addrs []string) string {
	result := ""
	for i, a := range addrs {
		if i > 0 {
			result += ", "
		}
		result += a
	}
	return result
}
