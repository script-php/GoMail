package delivery

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"gomail/auth"
	"gomail/config"
	"gomail/parser"
	"gomail/reporting"
	"gomail/smtp"
	"gomail/store"
)

// Worker processes outbound delivery queue entries.
type Worker struct {
	id       int
	db       *store.DB
	cfg      *config.Config
	tlsCfg   *tls.Config
	schedule *RetrySchedule
	claimMu  *sync.Mutex // shared mutex to prevent duplicate claims
}

// Pool manages a group of delivery workers.
type Pool struct {
	workers []*Worker
	db      *store.DB
	cfg     *config.Config
	tlsCfg  *tls.Config
	quit    chan struct{}
	wg      sync.WaitGroup
	claimMu sync.Mutex
}

// NewPool creates a delivery worker pool.
func NewPool(cfg *config.Config, db *store.DB, tlsCfg *tls.Config) *Pool {
	return &Pool{
		db:     db,
		cfg:    cfg,
		tlsCfg: tlsCfg,
		quit:   make(chan struct{}),
	}
}

// Start launches the delivery workers.
func (p *Pool) Start() {
	// Recover any stale entries stuck in "sending" status from previous crashes
	if recovered, err := p.db.RecoverStaleQueueEntries(); err != nil {
		log.Printf("[delivery] stale queue recovery error: %v", err)
	} else if recovered > 0 {
		log.Printf("[delivery] recovered %d stale queue entries", recovered)
	}

	schedule := NewRetrySchedule(p.cfg.Delivery.RetryIntervals)

	for i := 0; i < p.cfg.Delivery.QueueWorkers; i++ {
		w := &Worker{
			id:       i,
			db:       p.db,
			cfg:      p.cfg,
			tlsCfg:   p.tlsCfg,
			schedule: schedule,
			claimMu:  &p.claimMu,
		}
		p.workers = append(p.workers, w)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			w.run(p.quit)
		}()
	}

	log.Printf("[delivery] started %d workers", p.cfg.Delivery.QueueWorkers)
}

// Stop signals all workers to stop and waits for them to finish.
func (p *Pool) Stop() {
	close(p.quit)
	p.wg.Wait()
	log.Println("[delivery] all workers stopped")
}

func (w *Worker) run(quit chan struct{}) {
	ticker := time.NewTicker(10 * time.Second) // Poll every 10s
	defer ticker.Stop()

	for {
		select {
		case <-quit:
			return
		case <-ticker.C:
			w.processQueue()
		}
	}
}

func (w *Worker) processQueue() {
	// Claim one pending entry atomically (mutex prevents two workers from
	// grabbing the same entry).
	w.claimMu.Lock()
	entries, err := w.db.GetPendingQueue(1)
	if err != nil {
		w.claimMu.Unlock()
		log.Printf("[delivery] worker %d: queue read error: %v", w.id, err)
		return
	}
	if len(entries) == 0 {
		w.claimMu.Unlock()
		return
	}
	entry := entries[0]
	w.db.UpdateQueueEntry(entry.ID, "sending", entry.Attempts, entry.NextRetry, "")
	w.claimMu.Unlock()

	// Deliver outside the lock
	var deliveryErr error

	// Prepare message with ARC headers
	messageWithARC := w.addARCHeaders(entry.RawMessage, entry.MailFrom, parseRecipientDomain(entry.RcptTo))

	if w.isLocalRecipient(entry.RcptTo) {
		deliveryErr = w.deliverLocal(entry, messageWithARC)
	} else {
		// Get domain's requireTLS setting for outbound delivery
		domain := parseRecipientDomain(entry.RcptTo)
		requireTLS := false
		if domainRecord, err := w.db.GetDomainByName(domain); err == nil && domainRecord != nil {
			requireTLS = domainRecord.RequireTLS
		}

		deliveryErr = smtp.SendMail(
			entry.MailFrom,
			entry.RcptTo,
			messageWithARC,
			w.cfg.Server.Hostname,
			w.tlsCfg,
			requireTLS,
			entry.DSNNotify,
			entry.DSNRet,
			entry.DSNEnvID,
		)
	}

	if deliveryErr != nil {
		smtpCode := extractSMTPCode(deliveryErr.Error())
		isPermanent := isPermanentFailure(smtpCode)
		entry.Attempts++

		if isPermanent {
			// Permanent failure - stop retrying immediately
			log.Printf("[delivery] worker %d: permanent failure (code %d) for %s->%s after %d attempt(s): %v",
				w.id, smtpCode, entry.MailFrom, entry.RcptTo, entry.Attempts, deliveryErr)
			w.db.UpdateQueueEntry(entry.ID, "failed", entry.Attempts, time.Now().UTC(), deliveryErr.Error())

			// Send DSN if requested
			if err := w.sendDSNReport(entry, deliveryErr.Error(), smtpCode); err != nil {
				log.Printf("[delivery] DSN send failed: %v", err)
			}
		} else if entry.Attempts >= entry.MaxAttempts {
			// Temporary failure but max attempts reached
			log.Printf("[delivery] worker %d: temporary failure (code %d) but max attempts (%d) reached for %s->%s: %v",
				w.id, smtpCode, entry.MaxAttempts, entry.MailFrom, entry.RcptTo, deliveryErr)
			w.db.UpdateQueueEntry(entry.ID, "failed", entry.Attempts, time.Now().UTC(), deliveryErr.Error())

			// Send DSN if requested
			if err := w.sendDSNReport(entry, deliveryErr.Error(), smtpCode); err != nil {
				log.Printf("[delivery] DSN send failed: %v", err)
			}
		} else {
			// Temporary failure - retry
			nextRetry := w.schedule.NextRetry(entry.Attempts)
			log.Printf("[delivery] worker %d: temporary failure (code %d) for %s->%s (attempt %d/%d), retry at %s: %v",
				w.id, smtpCode, entry.MailFrom, entry.RcptTo, entry.Attempts, entry.MaxAttempts, nextRetry.Format(time.RFC3339), deliveryErr)
			w.db.UpdateQueueEntry(entry.ID, "pending", entry.Attempts, nextRetry, deliveryErr.Error())
		}
	} else {
		log.Printf("[delivery] worker %d: delivered %s->%s", w.id, entry.MailFrom, entry.RcptTo)
		w.db.UpdateQueueEntry(entry.ID, "sent", entry.Attempts+1, time.Now().UTC(), "")
	}
}

// isLocalRecipient checks if the recipient's domain is handled by this server.
func (w *Worker) isLocalRecipient(rcpt string) bool {
	parts := strings.SplitN(rcpt, "@", 2)
	if len(parts) != 2 {
		return false
	}
	domain := strings.ToLower(parts[1])

	domains, err := w.db.ListAllDomainNames()
	if err != nil {
		return false
	}
	for _, d := range domains {
		if strings.EqualFold(d, domain) {
			return true
		}
	}
	return false
}

// deliverLocal delivers a message directly to a local account's mailbox.
func (w *Worker) deliverLocal(entry *store.QueueEntry, messageWithARC []byte) error {
	rcpt := entry.RcptTo

	account, err := w.db.GetAccountByEmail(rcpt)
	if err != nil {
		return fmt.Errorf("account lookup for %s: %w", rcpt, err)
	}
	if account == nil {
		return fmt.Errorf("no local account for %s", rcpt)
	}
	if !account.IsActive {
		return fmt.Errorf("account %s is inactive", rcpt)
	}

	// Parse the message (use ARC-enhanced version)
	parsed, err := parser.Parse(messageWithARC)
	if err != nil {
		return fmt.Errorf("parsing message: %w", err)
	}

	// Add inbound Received header for local delivery (for consistency with external emails)
	receivedHeader := fmt.Sprintf("Received: from %s\r\n\tby %s\r\n\twith local\r\n\tid %s\r\n\tfor <%s>;\r\n\t%s\r\n",
		"localhost",
		w.cfg.Server.Hostname,
		fmt.Sprintf("%d@%s", time.Now().UnixNano(), w.cfg.Server.Hostname),
		rcpt,
		time.Now().Format(time.RFC1123Z),
	)
	rawMessageWithReceived := append([]byte(receivedHeader), messageWithARC...)

	// Extract raw headers directly from messageWithARC to preserve duplicate headers (like multiple ARC-* headers)
	// Don't use parsed.RawHeaders because parser loses duplicate header support
	var rawHeaders strings.Builder
	lines := strings.Split(string(messageWithARC), "\r\n")
	for _, line := range lines {
		if line == "" {
			break // End of headers
		}
		rawHeaders.WriteString(line)
		rawHeaders.WriteString("\r\n")
	}

	messageID := parsed.MessageID
	if messageID == "" {
		messageID = fmt.Sprintf("%d@%s", time.Now().UnixNano(), w.cfg.Server.Hostname)
	}

	rcptJSON, _ := json.Marshal([]string{rcpt})

	msg := &store.Message{
		AccountID:      account.ID,
		MessageID:      messageID,
		Direction:      "inbound",
		MailFrom:       entry.MailFrom,
		RcptTo:         string(rcptJSON),
		FromAddr:       parsed.From,
		ToAddr:         parsed.To,
		CcAddr:         parsed.Cc,
		ReplyTo:        parsed.ReplyTo,
		Subject:        parsed.Subject,
		TextBody:       parsed.TextBody,
		HTMLBody:       parsed.HTMLBody,
		RawHeaders:     rawHeaders.String(),
		RawMessage:     rawMessageWithReceived,
		Size:           int64(len(rawMessageWithReceived)),
		HasAttachments: len(parsed.Attachments) > 0,
		SPFResult:      "none",
		DKIMResult:     "none",
		DMARCResult:    "none",
		AuthResults:    "local-delivery",
		MDNRequested:   parsed.MDNRequestedBy != "",
		MDNAddress:     parsed.MDNRequestedBy,
		ReceivedAt:     time.Now(),
	}

	// Assign to inbox folder
	inboxFolder, err := w.db.GetFolderByType(account.ID, "inbox")
	if err != nil {
		return fmt.Errorf("getting inbox folder: %w", err)
	}
	if inboxFolder != nil {
		msg.FolderID = &inboxFolder.ID
	}

	msgID, err := w.db.SaveMessage(msg)
	if err != nil {
		return fmt.Errorf("saving message for %s: %w", rcpt, err)
	}

	// Update folder counts
	if msg.FolderID != nil {
		w.db.UpdateFolderCounts(*msg.FolderID)
	}

	// Save attachments
	if len(parsed.Attachments) > 0 {
		records, err := parser.SaveAttachments(parsed.Attachments, msgID, w.db.AttachmentsPath())
		if err != nil {
			log.Printf("[delivery] local attachment save error: %v", err)
		} else {
			for _, rec := range records {
				if _, err := w.db.SaveAttachment(rec); err != nil {
					log.Printf("[delivery] local attachment db save error: %v", err)
				}
			}
		}
	}

	log.Printf("[delivery] local delivery: id=%d from=%s to=%s subject=%s (rawmessage_size=%d)",
		msgID, entry.MailFrom, rcpt, parsed.Subject, len(rawMessageWithReceived))
	return nil
}

// addARCHeaders attempts to add ARC headers to the message if DKIM key is available
// Returns the modified message or original if ARC signing fails (non-fatal)
func (w *Worker) addARCHeaders(msg []byte, mailFrom, rcptDomain string) []byte {
	// Extract sender domain
	parts := strings.SplitN(mailFrom, "@", 2)
	if len(parts) != 2 {
		return msg // Can't extract domain, return original
	}
	senderDomain := parts[1]

	// Get domain config including DKIM info
	domain, err := w.db.GetDomainByName(senderDomain)
	if err != nil || domain == nil {
		// Silently skip if domain not found (not an error for Arc, optional feature)
		return msg
	}

	// Check if domain has DKIM key
	if domain.DKIMPrivateKey == "" || domain.DKIMSelector == "" {
		// No DKIM key, skip ARC signing (ARC requires valid crypto keys)
		return msg
	}

	// Load DKIM signer
	algorithm := "rsa"
	if domain.DKIMAlgorithm != "" {
		algorithm = domain.DKIMAlgorithm
	}

	signer, err := auth.NewDKIMSignerFromPEM(senderDomain, domain.DKIMSelector, []byte(domain.DKIMPrivateKey), algorithm)
	if err != nil {
		log.Printf("[delivery] warning: failed to load DKIM key for ARC: %v", err)
		return msg
	}

	// Generate ARC chain
	// For outbound messages, always use instance=1 (this is the originating hop)
	// For forwarded messages, use instance returned by auth.NextArcInstance()
	instance := auth.NextArcInstance(msg)
	highest := auth.GetHighestArcInstance(msg)
	log.Printf("[delivery] ARC chain: detecting instance for message size=%d, highest_found=%d, next_instance=%d", len(msg), highest, instance)

	arcHeaders, err := auth.ARCChainSigner(
		senderDomain,
		domain.DKIMSelector,
		signer.PrivateKey,
		"pass", // SPF (originating from GoMail, trusted)
		"pass", // DKIM (will sign this message)
		"pass", // DMARC
		w.cfg.Server.Hostname,
		string(msg),
		instance, // instance: i=1 for new, i=2+ for forwarding
	)
	if err != nil {
		log.Printf("[delivery] warning: ARC signing failed: %v", err)
		return msg // Return original on ARC signing failure
	}

	log.Printf("[delivery] ARC chain: generated %d headers at instance=%d", len(arcHeaders), instance)
	for i, h := range arcHeaders {
		log.Printf("[delivery] ARC chain header %d: %.100s...", i+1, h)
	}

	// Prepend ARC headers to message (in order: auth-results, message-signature, seal)
	// Remove any trailing whitespace and rebuild with ARC headers first
	arcHeadersStr := strings.Join(arcHeaders, "\r\n") + "\r\n"
	modifiedMsg := append([]byte(arcHeadersStr), msg...)

	log.Printf("[delivery] ARC headers prepended, new message size=%d", len(modifiedMsg))
	return modifiedMsg
}

// parseRecipientDomain extracts the domain from an email address
func parseRecipientDomain(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

// extractSMTPCode extracts SMTP reply code from error message.
// Example: "message rejected by host.com: 550 5.1.1 user unknown"
func extractSMTPCode(errMsg string) int {
	parts := strings.Fields(errMsg)
	for _, part := range parts {
		if len(part) == 3 {
			// Try to parse as 3-digit SMTP code
			var code int
			if _, err := fmt.Sscanf(part, "%d", &code); err == nil && code >= 400 && code <= 599 {
				return code
			}
		}
	}
	// Default to generic server error if no code found
	return 550
}

// isPermanentFailure determines if an SMTP error is permanent (should not retry) or temporary.
// RFC 5321: The first digit indicates:
//   - 4xx = Permanent negative reply
//   - 5xx = Transient negative reply (but some 5xx codes like 554, 550 are actually permanent in practice)
//
// Permanent failures (fail immediately, no retry):
//   - 550: Unrouteable address (user/domain unknown)
//   - 551: User not local; please try <forward-path>
//   - 552: Storage limit exceeded
//   - 553: Invalid address
//   - 554: Message rejected
//   - 500, 501, 502, 504, 505: Command/syntax errors
//
// Temporary failures (should retry):
//   - 421, 450, 451, 452, 455: Service temporarily unavailable
//   - 503: Service unavailable (also temporary despite 5xx)
func isPermanentFailure(smtpCode int) bool {
	// Permanent failures - fail immediately
	if smtpCode == 550 || smtpCode == 551 || smtpCode == 552 || smtpCode == 553 || smtpCode == 554 ||
		smtpCode == 500 || smtpCode == 501 || smtpCode == 502 || smtpCode == 504 || smtpCode == 505 {
		return true
	}

	// Temporary failures - should retry
	if smtpCode == 421 || smtpCode == 450 || smtpCode == 451 || smtpCode == 452 || smtpCode == 455 ||
		smtpCode == 503 {
		return false
	}

	// Default heuristic:
	// - 4xx codes are usually permanent
	// - 5xx codes are usually temporary (except the ones we already handled above)
	if smtpCode >= 400 && smtpCode < 500 {
		return true
	}
	return false
}

// sendDSNReport sends a Delivery Status Notification (DSN) for a delivery failure.
// Only sends if DSN was requested via the NOTIFY parameter.
func (w *Worker) sendDSNReport(entry *store.QueueEntry, errorMsg string, smtpCode int) error {
	// Skip if no DSN notification was requested or already sent
	if entry.DSNNotify == "" || entry.DSNSent || entry.MailFrom == "" {
		return nil
	}

	// Check if FAILURE notification was requested
	if !strings.Contains(entry.DSNNotify, "FAILURE") {
		return nil
	}

	log.Printf("[delivery] sending DSN for failed delivery to %s (from %s)", entry.RcptTo, entry.MailFrom)

	// Import DSN reporting package
	dsnReport, err := buildDSNMessage(
		w.cfg.Server.Hostname,
		entry.RcptTo,
		entry.MailFrom,
		"failed",
		errorMsg,
		smtpCode,
		entry.DSNEnvID,
	)
	if err != nil {
		log.Printf("[delivery] failed to build DSN: %v", err)
		return err
	}

	// Send DSN as an inbound message to the sender's mailbox (reverse path)
	if err := w.deliverDSN(entry.MailFrom, dsnReport); err != nil {
		log.Printf("[delivery] failed to deliver DSN to %s: %v", entry.MailFrom, err)
		return err
	}

	// Mark DSN as sent
	w.db.MarkDSNSent(entry.ID)

	return nil
}

// deliverDSN stores a DSN report message in the sender's mailbox.
func (w *Worker) deliverDSN(senderEmail string, dsnReport string) error {
	account, err := w.db.GetAccountByEmail(senderEmail)
	if err != nil || account == nil {
		return fmt.Errorf("account not found for DSN: %s", senderEmail)
	}

	// Parse DSN as an inbound message
	parsed, err := parser.Parse([]byte(dsnReport))
	if err != nil {
		return fmt.Errorf("parsing DSN message: %w", err)
	}

	// Add Received header
	receivedHeader := fmt.Sprintf("Received: from %s\r\n\tby %s\r\n\twith local\r\n\tid %s\r\n\tfor <%s>;\r\n\t%s\r\n",
		w.cfg.Server.Hostname,
		w.cfg.Server.Hostname,
		fmt.Sprintf("%d@%s", time.Now().UnixNano(), w.cfg.Server.Hostname),
		senderEmail,
		time.Now().Format(time.RFC1123Z),
	)

	msg := &store.Message{
		AccountID:  account.ID,
		MessageID:  fmt.Sprintf("%d@%s", time.Now().UnixNano(), w.cfg.Server.Hostname),
		Direction:  "inbound",
		MailFrom:   fmt.Sprintf("Mailer-Daemon@%s", w.cfg.Server.Hostname),
		RcptTo:     senderEmail,
		FromAddr:   fmt.Sprintf("Mailer-Daemon@%s", w.cfg.Server.Hostname),
		ToAddr:     senderEmail,
		Subject:    parsed.Subject,
		TextBody:   parsed.TextBody,
		HTMLBody:   parsed.HTMLBody,
		RawHeaders: receivedHeader + parsed.RawHeaders,
		RawMessage: append([]byte(receivedHeader), dsnReport...),
		Size:       int64(len(dsnReport)),
		IsRead:     false,
		ReceivedAt: time.Now(),
	}

	// Store in Inbox
	inboxFolder, err := w.db.GetFolderByType(account.ID, "inbox")
	if err == nil && inboxFolder != nil {
		msg.FolderID = &inboxFolder.ID
	}

	if _, err := w.db.SaveMessage(msg); err != nil {
		return fmt.Errorf("saving DSN message: %w", err)
	}

	return nil
}

// buildDSNMessage constructs an RFC 3464 DSN report message.
func buildDSNMessage(
	reportingMTA string,
	failedRecipient string,
	originalSender string,
	action string,
	diagnosticText string,
	smtpCode int,
	envID string,
) (string, error) {
	statusCode := reporting.StatusCodeFromSMTPCode(smtpCode)

	// Build multipart DSN message
	boundary := fmt.Sprintf("boundary-%d", time.Now().UnixNano())
	subjectLine := fmt.Sprintf("Delivery Status Notification (Failure)")

	msg := fmt.Sprintf(`From: Mailer-Daemon@%s
To: %s
Subject: %s
Date: %s
MIME-Version: 1.0
Content-Type: multipart/report; report-type=delivery-status; boundary=%s
Message-ID: <%d@%s>

--%s
Content-Type: text/plain; charset=UTF-8

The following message could not be delivered to: %s

Original-Message-ID: %s
Last-Attempt-Date: %s

--%s
Content-Type: message/delivery-status

Reporting-MTA: dns; %s
Action: %s
Status: %s
Diagnostic-Code: smtp; %d %s
Final-Recipient: rfc822; %s

--%s--
`,
		reportingMTA,
		originalSender,
		subjectLine,
		time.Now().UTC().Format(time.RFC1123Z),
		boundary,
		time.Now().UnixNano(),
		reportingMTA,
		boundary,
		failedRecipient,
		envID,
		time.Now().UTC().Format(time.RFC3339),
		boundary,
		reportingMTA,
		action,
		statusCode,
		smtpCode,
		diagnosticText,
		failedRecipient,
		boundary,
	)

	return msg, nil
}
