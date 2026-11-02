package delivery

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gomail/auth"
	"gomail/config"
	"gomail/logging"
	"gomail/parser"
	"gomail/smtp"
	"gomail/store"
)

// ErrInvalidMessage indicates that the message cannot be transmitted as SMTP DATA.
var ErrInvalidMessage = errors.New("invalid outbound message")

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
	return q.enqueue(from, to, nil, rawMessage, accountID, 0)
}

// SubmissionDSN carries authenticated clients' DSN options into the durable queue.
type SubmissionDSN struct {
	Notify            []string
	OriginalRecipient []string
	Return            string
	EnvelopeID        string
}

// EnqueueSubmission preserves per-recipient DSN requests from authenticated SMTP clients.
func (q *Queue) EnqueueSubmission(from string, to []string, dsn SubmissionDSN, rawMessage []byte, accountID int64) error {
	if len(to) != len(dsn.Notify) || len(to) != len(dsn.OriginalRecipient) {
		return fmt.Errorf("recipient and DSN option counts differ")
	}
	return q.enqueue(from, to, &dsn, rawMessage, accountID, 0)
}

// EnqueueMDN commits the receipt and its source-message marker together.
func (q *Queue) EnqueueMDN(from string, to []string, rawMessage []byte, accountID, sourceMessageID int64) error {
	return q.enqueue(from, to, nil, rawMessage, accountID, sourceMessageID)
}

func (q *Queue) enqueue(from string, to []string, dsn *SubmissionDSN, rawMessage []byte, accountID, mdnSourceID int64) error {
	// Normalize eligible MIME bodies before DKIM signs them. A DKIM-signed
	// seven-bit representation can be delivered to both modern and legacy
	// SMTP peers without changing the queued signature at delivery time.
	rawMessage = sevenBitMIME(rawMessage)
	if err := smtp.ValidateSMTPDataLines(rawMessage); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
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
	if err := smtp.ValidateSMTPDataLines(signedMessage); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}

	// Store the outbound message in the messages table
	rcptJSON, err := json.Marshal(to)
	if err != nil {
		return fmt.Errorf("encoding recipients: %w", err)
	}

	// Parse the SIGNED message to extract subject, body, headers for the sent view
	// (includes DKIM-Signature header if signing succeeded)
	parsed, err := parser.Parse(signedMessage)
	if err != nil {
		return fmt.Errorf("parsing signed message before queueing: %w", err)
	}
	var subject, textBody, htmlBody, rawHeaders, toAddr, ccAddr string
	subject = parsed.Subject
	textBody = parsed.TextBody
	htmlBody = parsed.HTMLBody
	rawHeaders = parsed.RawHeaders
	toAddr = parsed.To
	ccAddr = parsed.Cc
	if toAddr == "" {
		toAddr = joinAddrs(to)
	}
	messageID := parsed.MessageID
	if messageID == "" {
		// The identifier is only a local placeholder when the submitted
		// message omitted Message-ID; do not modify MIME after DKIM signing.
		messageID = fmt.Sprintf("%d@%s", time.Now().UnixNano(), q.cfg.Server.Hostname)
	}

	msg := &store.Message{
		AccountID:      accountID,
		MessageID:      messageID,
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
		HasAttachments: len(parsed.Attachments) > 0,
		IsRead:         true, // Outbound messages are already "read"
		ReceivedAt:     time.Now(),
	}

	// System-generated reports have no mailbox or Sent folder; their queued
	// raw MIME remains the durable copy until delivery completes.
	if accountID != 0 {
		sentFolder, err := q.db.GetFolderByType(accountID, "sent")
		if err != nil {
			return fmt.Errorf("loading sent folder: %w", err)
		}
		if sentFolder == nil {
			return fmt.Errorf("account %d has no sent folder", accountID)
		}
		msg.FolderID = &sentFolder.ID
	}

	var entries []*store.QueueEntry
	// Create a queue entry for each recipient
	for index, rcpt := range to {
		// Generate VERP bounce address for automatic bounce tracking (if enabled)
		var verpAddr string
		if q.cfg.Delivery.IsVERPEnabled() {
			var err error
			verpAddr, err = q.db.EncodeVERP(from, rcpt)
			if err != nil {
				logging.Info(fmt.Sprintf("[delivery] VERP encoding failed for %s -> %s: %v (using regular address)", from, rcpt, err))
				verpAddr = "" // Empty means the worker uses the ordinary sender address.
			}
		}

		dsnNotify := "FAILURE"
		dsnRet := "FULL"
		dsnEnvID := msg.MessageID
		originalRecipient := rcpt
		if dsn != nil {
			// Preserve absence of DSN parameters from submission when relaying.
			dsnRet, dsnEnvID = "", ""
			dsnNotify = dsn.Notify[index]
			if dsn.Return != "" {
				dsnRet = dsn.Return
			}
			if dsn.EnvelopeID != "" {
				dsnEnvID = dsn.EnvelopeID
			}
			if dsn.OriginalRecipient[index] != "" {
				originalRecipient = dsn.OriginalRecipient[index]
			}
		}
		entry := &store.QueueEntry{

			MailFrom:          from,
			RcptTo:            rcpt,
			RawMessage:        signedMessage,
			MaxAttempts:       q.cfg.Delivery.MaxRetries,
			NextRetry:         time.Now().UTC(),
			DSNNotify:         dsnNotify,
			DSNRet:            dsnRet,
			DSNEnvID:          dsnEnvID,
			VERPBounceAddress: verpAddr, // VERP-encoded bounce address (empty if disabled)
			OriginalRecipient: originalRecipient,
		}

		entries = append(entries, entry)
	}
	// System-generated messages have no Sent-folder owner. Their raw MIME is
	// fully queued for delivery, but decoded sidecars have nowhere to belong.
	var attachments []store.IMAPAppendAttachment
	if accountID != 0 {
		attachments = make([]store.IMAPAppendAttachment, 0, len(parsed.Attachments))
		for _, attachment := range parsed.Attachments {
			attachments = append(attachments, store.IMAPAppendAttachment{Filename: attachment.Filename, ContentType: attachment.ContentType, Data: attachment.Data})
		}
	}
	var msgID int64
	if mdnSourceID != 0 {
		msgID, err = q.db.SaveQueuedMDNMessageWithAttachments(msg, entries, mdnSourceID, attachments)
	} else {
		msgID, err = q.db.SaveQueuedMessageWithAttachments(msg, entries, attachments)
	}
	if err != nil {
		return fmt.Errorf("queueing outbound message: %w", err)
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
