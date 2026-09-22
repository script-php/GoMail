package delivery

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gomail/auth"
	"gomail/config"
	"gomail/logging"
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
func (q *Queue) getDKIMSigner(from string) (*auth.DKIMSigner, error) {
	domain := extractDomain(from)
	if domain == "" {
		return nil, fmt.Errorf("invalid sender address")
	}

	d, err := q.db.GetDomainByName(domain)
	if err != nil {
		return nil, fmt.Errorf("loading sender domain: %w", err)
	}
	if d == nil {
		return nil, fmt.Errorf("sender domain %s is not managed", domain)
	}
	if !d.IsActive {
		return nil, fmt.Errorf("sender domain %s is inactive", domain)
	}
	if d.DKIMSelector == "" || d.DKIMAlgorithm == "" {
		return nil, fmt.Errorf("DKIM is not configured for %s", domain)
	}
	if d.DKIMPrivateKey == "" {
		return nil, fmt.Errorf("DKIM private key is missing for %s", domain)
	}

	signer, err := auth.NewDKIMSignerFromPEM(d.Domain, d.DKIMSelector, []byte(d.DKIMPrivateKey), d.DKIMAlgorithm)
	if err != nil {
		logging.Info(fmt.Sprintf("[delivery] DKIM signer init failed for %s: %v", domain, err))
		return nil, err
	}
	return signer, nil
}

// Enqueue adds a new outbound message to the delivery queue.
// It DKIM-signs the message (per-domain), stores it, and creates queue entries.
func (q *Queue) Enqueue(from string, to []string, rawMessage []byte, accountID int64) error {
	// Per-domain DKIM signing
	signer, signerErr := q.getDKIMSigner(from)
	if signerErr != nil {
		return fmt.Errorf("refusing unsigned delivery: %w", signerErr)
	}
	var signedMessage []byte
	if signer != nil {
		var err error
		signedMessage, err = signer.Sign(rawMessage)
		if err != nil {
			return fmt.Errorf("refusing unsigned delivery after DKIM signing failure: %w", err)
		} else {
			logging.Info(fmt.Sprintf("[delivery] DKIM signed with selector=%s domain=%s", signer.Selector, signer.Domain))
		}
	}

	// Store the outbound message in the messages table
	rcptJSON, _ := json.Marshal(to)

	// Parse the SIGNED message to extract subject, body, headers for the sent view
	// (includes DKIM-Signature header if signing succeeded)
	parsed, _ := parser.Parse(signedMessage)
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
		AccountID:      accountID,
		MessageID:      fmt.Sprintf("%d@%s", time.Now().UnixNano(), q.cfg.Server.Hostname),
		Direction:      "outbound",
		MailFrom:       from,
		RcptTo:         string(rcptJSON),
		FromAddr:       from,
		ToAddr:         toAddr,
		CcAddr:         ccAddr,
		Subject:        subject,
		TextBody:       textBody,
		HTMLBody:       htmlBody,
		RawHeaders:     rawHeaders,
		RawMessage:     signedMessage,
		Size:           int64(len(signedMessage)),
		HasAttachments: parsed != nil && len(parsed.Attachments) > 0,
		IsRead:         true, // Outbound messages are already "read"
		ReceivedAt:     time.Now(),
	}

	// Assign outbound message to Sent folder
	sentFolder, err := q.db.GetFolderByType(accountID, "sent")
	if err == nil && sentFolder != nil {
		msg.FolderID = &sentFolder.ID
	}

	var entries []*store.QueueEntry
	// Create a queue entry for each recipient
	for _, rcpt := range to {
		// Generate VERP bounce address for automatic bounce tracking (if enabled)
		var verpAddr string
		if q.cfg.Delivery.IsVERPEnabled() {
			var err error
			verpAddr, err = q.db.EncodeVERP(from, rcpt)
			if err != nil {
				logging.Info(fmt.Sprintf("[delivery] VERP encoding failed for %s -> %s: %v (using regular address)", from, rcpt, err))
				verpAddr = from // Fallback to normal address if VERP fails
			}
		}

		entry := &store.QueueEntry{

			MailFrom:          from,
			RcptTo:            rcpt,
			RawMessage:        signedMessage,
			MaxAttempts:       q.cfg.Delivery.MaxRetries,
			NextRetry:         time.Now().UTC(),
			DSNNotify:         "FAILURE", // Request failure notifications from remote server
			DSNRet:            "FULL",    // Request full message in failure report
			DSNEnvID:          msg.MessageID,
			VERPBounceAddress: verpAddr, // VERP-encoded bounce address (empty if disabled)
			OriginalRecipient: rcpt,     // Store original recipient for tracking
		}

		entries = append(entries, entry)
	}
	msgID, err := q.db.SaveQueuedMessage(msg, entries)
	if err != nil {
		return fmt.Errorf("queueing outbound message: %w", err)
	}
	// Save attachments from the parsed message
	if parsed != nil && len(parsed.Attachments) > 0 {
		records, err := parser.SaveAttachments(parsed.Attachments, msgID, q.cfg.Store.AttachmentsPath)
		if err != nil {
			logging.Info(fmt.Sprintf("[delivery] attachment save error: %v", err))
		} else {
			for _, rec := range records {
				if _, err := q.db.SaveAttachment(rec); err != nil {
					logging.Info(fmt.Sprintf("[delivery] failed to save attachment record: %v", err))
				}
			}
		}
	}

	// Update sent folder counts
	if msg.FolderID != nil {
		q.db.UpdateFolderCounts(*msg.FolderID)
	}

	logging.Info(fmt.Sprintf("[delivery] enqueued message from=%s to=%v id=%d", from, to, msgID))
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
