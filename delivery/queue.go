package delivery

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"gomail/auth"
	"gomail/config"
	"gomail/parser"
	"gomail/store"
)

// Queue manages the outbound message delivery queue.
type Queue struct {
	db  *store.DB
	cfg *config.Config
}

// NewQueue creates a delivery queue manager.
func NewQueue(db *store.DB, cfg *config.Config) *Queue {
	return &Queue{
		db:  db,
		cfg: cfg,
	}
}

// getDKIMSigner returns a DKIM signer for the sender's domain (from DB).
func (q *Queue) getDKIMSigner(from string) *auth.DKIMSigner {
	domain := extractDomain(from)
	if domain == "" {
		return nil
	}

	d, err := q.db.GetDomainByName(domain)
	if err != nil || d == nil {
		return nil
	}
	if d.DKIMPrivateKey == "" {
		return nil
	}

	signer, err := auth.NewDKIMSignerFromPEM(d.Domain, d.DKIMSelector, []byte(d.DKIMPrivateKey), d.DKIMAlgorithm)
	if err != nil {
		log.Printf("[delivery] DKIM signer init failed for %s: %v", domain, err)
		return nil
	}
	return signer
}

// Enqueue adds a new outbound message to the delivery queue.
// It DKIM-signs the message (per-domain), stores it, and creates queue entries.
func (q *Queue) Enqueue(from string, to []string, rawMessage []byte, accountID int64) error {
	// Per-domain DKIM signing
	signer := q.getDKIMSigner(from)
	var signedMessage []byte
	if signer != nil {
		var err error
		signedMessage, err = signer.Sign(rawMessage)
		if err != nil {
			log.Printf("[delivery] DKIM signing failed: %v (sending unsigned)", err)
			signedMessage = rawMessage
		} else {
			log.Printf("[delivery] DKIM signed with selector=%s domain=%s", signer.Selector, signer.Domain)
		}
	} else {
		signedMessage = rawMessage
	}

	// Store the outbound message in the messages table
	rcptJSON, _ := json.Marshal(to)

	// Parse the message to extract subject, body, headers for the sent view
	parsed, _ := parser.Parse(rawMessage)
	var subject, textBody, htmlBody, rawHeaders, toAddr, ccAddr string
	if parsed != nil {
		subject = parsed.Subject
		textBody = parsed.TextBody
		htmlBody = parsed.HTMLBody
		rawHeaders = parsed.RawHeaders
		toAddr = parsed.To
		ccAddr = parsed.Cc
	}
	if toAddr == "" {
		toAddr = joinAddrs(to)
	}

	msg := &store.Message{
		AccountID:  accountID,
		MessageID:  fmt.Sprintf("%d@%s", time.Now().UnixNano(), q.cfg.Server.Hostname),
		Direction:  "outbound",
		MailFrom:   from,
		RcptTo:     string(rcptJSON),
		FromAddr:   from,
		ToAddr:     toAddr,
		CcAddr:     ccAddr,
		Subject:    subject,
		TextBody:   textBody,
		HTMLBody:   htmlBody,
		RawHeaders: rawHeaders,
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
			NextRetry:   time.Now().UTC(),
		}

		if _, err := q.db.EnqueueMessage(entry); err != nil {
			log.Printf("[delivery] enqueue error for %s: %v", rcpt, err)
		}
	}

	log.Printf("[delivery] enqueued message from=%s to=%v id=%d", from, to, msgID)
	return nil
}

func extractDomain(addr string) string {
	parts := strings.SplitN(addr, "@", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
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
