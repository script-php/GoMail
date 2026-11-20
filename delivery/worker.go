package delivery

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"

	"gomail/config"
	"gomail/metrics"
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

var errLocalMailboxMissing = errors.New("local mailbox does not exist")
var errLocalMailboxInactive = errors.New("local mailbox is inactive")
var errLocalDomainInactive = errors.New("local domain is missing or inactive")

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
	// Quarantine stale claims; SMTP may already have accepted the message.
	p.recoverStaleQueueEntries()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.runQueueRecovery(5 * time.Minute)
	}()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.runQueueRetention()
	}()

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

func (p *Pool) recoverStaleQueueEntries() {
	if recovered, err := p.db.RecoverStaleQueueEntries(); err != nil {
		log.Printf("[delivery] stale queue recovery error: %v", err)
	} else if recovered > 0 {
		log.Printf("[delivery] quarantined %d uncertain queue entries for operator review", recovered)
	}
}

func (p *Pool) runQueueRecovery(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.quit:
			return
		case <-ticker.C:
			p.recoverStaleQueueEntries()
		}
	}
}

func (p *Pool) runQueueRetention() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-p.quit:
			return
		case <-ticker.C:
			now := time.Now().UTC()
			days, err := p.db.QueueRetentionDays()
			if err != nil {
				log.Printf("[delivery] queue retention settings: %v", err)
			} else if days > 0 {
				removed, err := p.db.PruneCompletedQueueEntries(days, now, 500)
				if err != nil {
					log.Printf("[delivery] queue retention: %v", err)
				} else if removed > 0 {
					log.Printf("[delivery] removed %d expired terminal queue entries", removed)
				}
			}
			verpDays, err := p.db.VERPRetentionDays()
			if err != nil {
				log.Printf("[delivery] VERP retention settings: %v", err)
			} else if verpDays > 0 {
				removed, err := p.db.PruneIssuedVERP(verpDays, now, 500)
				if err != nil {
					log.Printf("[delivery] VERP retention: %v", err)
				} else if removed > 0 {
					log.Printf("[delivery] removed %d expired VERP mappings", removed)
				}
			}
		}
	}
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
	w.processFinalDSNs()
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
	token, claimed, err := w.db.ClaimQueueEntry(entry.ID)
	if err != nil || !claimed {
		w.claimMu.Unlock()
		if err != nil {
			log.Printf("[delivery] claim failed: %v", err)
		}
		return
	}
	w.claimMu.Unlock()
	stopHeartbeat := w.startClaimHeartbeat(entry.ID, token)
	allowed, reason, senderErr := w.db.QueueSenderAllowed(entry, time.Now().UTC())
	if senderErr != nil {
		stopHeartbeat()
		if err := w.transitionOwnedQueue(entry.ID, token, "pending", entry.Attempts, time.Now().UTC().Add(time.Minute), senderErr.Error(), 0, ""); err != nil {
			w.logStatePersistenceFailure(entry, "pending", err)
		}
		return
	}
	if !allowed {
		stopHeartbeat()
		if err := w.transitionOwnedQueue(entry.ID, token, "cancelled", entry.Attempts, time.Now().UTC(), reason, 0, ""); err != nil {
			w.logStatePersistenceFailure(entry, "cancelled", err)
		}
		return
	}

	// Deliver outside the lock
	var deliveryErr error

	// Locally originated mail is DKIM-signed at enqueue time. ARC is only for
	// intermediaries preserving authentication across a forward/relay hop.
	messageForDelivery := entry.RawMessage

	// Use VERP bounce address in MAIL FROM if available, otherwise use original sender
	mailFromAddr := queueReversePath(entry)
	if entry.VERPBounceAddress != "" {
		log.Printf("[delivery] using VERP bounce address: %s (original: %s)", mailFromAddr, entry.MailFrom)
	}

	isLocal := entry.LocalRecipient
	var routeErr error
	if !isLocal {
		isLocal, routeErr = w.isLocalRecipient(entry.RcptTo)
	}
	if routeErr != nil {
		deliveryErr = fmt.Errorf("checking recipient route: %w", routeErr)
	} else if isLocal {
		deliveryErr = w.deliverLocalClaimed(entry, token, messageForDelivery)
	} else {
		// Outbound transport policy belongs to the sender's managed domain.
		domain := parseRecipientDomain(entry.MailFrom)
		if entry.MailFrom == "" {
			domain = w.cfg.Server.Domain
			if domain == "" {
				domain = w.cfg.Server.Hostname
			}
		}
		requireTLS := false
		domainRecord, policyErr := w.db.GetDomainByName(domain)
		if policyErr != nil {
			deliveryErr = fmt.Errorf("loading sender transport policy: %w", policyErr)
		} else if domainRecord == nil || !domainRecord.IsActive {
			deliveryErr = fmt.Errorf("sender domain is missing or inactive")
		} else {
			requireTLS = domainRecord.RequireTLS
			send := smtp.SendMail
			if entry.TLSReport && entry.OriginAccountID == 0 {
				send = func(from, to string, msg []byte, hostname string, tlsCfg *tls.Config, _ bool, dsnNotify, dsnRet, dsnEnvID, network string, db *store.DB, policyDomain ...string) error {
					return smtp.SendTLSReport(from, to, msg, hostname, tlsCfg, dsnNotify, dsnRet, dsnEnvID, network, db, policyDomain...)
				}
			}
			deliveryErr = send(
				mailFromAddr,
				entry.RcptTo,
				messageForDelivery,
				w.cfg.Server.Hostname,
				w.tlsCfg,
				requireTLS,
				entry.DSNNotify,
				entry.DSNRet,
				entry.DSNEnvID,
				w.cfg.Delivery.GetNetwork(),
				w.db,
				domain,
				entry.OriginalRecipient,
			)
		}
	}
	stopHeartbeat()

	if deliveryErr != nil {
		if errors.Is(deliveryErr, store.ErrQueueClaimLost) {
			w.logStatePersistenceFailure(entry, "local delivery", deliveryErr)
			return // Never requeue a claim that may have been resolved elsewhere.
		}
		if errors.Is(deliveryErr, smtp.ErrDeliveryOutcomeUnknown) {
			entry.Attempts++
			metrics.IncDelivery("uncertain")
			log.Printf("[delivery] worker %d: outcome unknown for queue entry %d; operator review required: %v", w.id, entry.ID, deliveryErr)
			if err := w.transitionOwnedQueue(entry.ID, token, "uncertain", entry.Attempts, time.Now().UTC(), deliveryErr.Error(), 0, ""); err != nil {
				w.logStatePersistenceFailure(entry, "uncertain", err)
			}
			return
		}
		smtpCode := smtp.SMTPFailureCode(deliveryErr)
		if errors.Is(deliveryErr, errLocalMailboxMissing) || errors.Is(deliveryErr, errLocalMailboxInactive) || errors.Is(deliveryErr, errLocalDomainInactive) {
			smtpCode = 550
		}
		if errors.Is(deliveryErr, store.ErrQuotaExceeded) {
			metrics.IncQuota("delivery")
			smtpCode = 452
		}
		isPermanent := isPermanentFailure(smtpCode)
		entry.Attempts++

		if isPermanent {
			metrics.IncDelivery("failed")
			// Permanent failure - stop retrying immediately
			log.Printf("[delivery] worker %d: permanent failure (code %d) for %s->%s after %d attempt(s): %v",
				w.id, smtpCode, entry.MailFrom, entry.RcptTo, entry.Attempts, deliveryErr)
			if err := w.transitionOwnedQueue(entry.ID, token, "failed", entry.Attempts, time.Now().UTC(), deliveryErr.Error(), smtpCode, ""); err != nil {
				w.logStatePersistenceFailure(entry, "failed", err)
				return
			}

			// Send DSN if requested
			w.sendFinalDSNOrSchedule(entry, "failed", deliveryErr.Error(), smtpCode)
		} else if entry.Attempts >= entry.MaxAttempts {
			metrics.IncDelivery("failed")
			// Temporary failure but max attempts reached
			log.Printf("[delivery] worker %d: temporary failure (code %d) but max attempts (%d) reached for %s->%s: %v",
				w.id, smtpCode, entry.MaxAttempts, entry.MailFrom, entry.RcptTo, deliveryErr)
			if err := w.transitionOwnedQueue(entry.ID, token, "failed", entry.Attempts, time.Now().UTC(), deliveryErr.Error(), smtpCode, ""); err != nil {
				w.logStatePersistenceFailure(entry, "failed", err)
				return
			}

			// Send DSN if requested
			w.sendFinalDSNOrSchedule(entry, "failed", deliveryErr.Error(), smtpCode)
		} else {
			metrics.IncDelivery("retry")
			// Temporary failure - retry
			nextRetry := w.schedule.NextRetry(entry.Attempts)
			log.Printf("[delivery] worker %d: temporary failure (code %d) for %s->%s (attempt %d/%d), retry at %s: %v",
				w.id, smtpCode, entry.MailFrom, entry.RcptTo, entry.Attempts, entry.MaxAttempts, nextRetry.Format(time.RFC3339), deliveryErr)
			if err := w.transitionOwnedQueue(entry.ID, token, "pending", entry.Attempts, nextRetry, deliveryErr.Error(), smtpCode, ""); err != nil {
				w.logStatePersistenceFailure(entry, "pending", err)
				return
			}
			if !entry.DSNDelaySent && time.Since(entry.CreatedAt) >= time.Duration(w.cfg.Delivery.DSNDelayAfterSeconds)*time.Second {
				if err := w.sendRequestedDSN(entry, "delayed", deliveryErr.Error(), smtpCode); err != nil {
					log.Printf("[delivery] delayed DSN send failed: %v", err)
				}
			}
		}
	} else {
		metrics.IncDelivery("delivered")
		log.Printf("[delivery] worker %d: delivered %s->%s", w.id, entry.MailFrom, entry.RcptTo)
		successDetail := "outbound SMTP send returned success"
		if isLocal {
			successDetail = "local mailbox delivery completed"
		}
		if !isLocal {
			if err := w.transitionOwnedQueue(entry.ID, token, "sent", entry.Attempts+1, time.Now().UTC(), "", 0, successDetail); err != nil {
				w.logStatePersistenceFailure(entry, "sent", err)
				return
			}
		}
		w.sendFinalDSNOrSchedule(entry, "delivered", "delivery completed", 250)
	}
}

func (w *Worker) startClaimHeartbeat(id int64, token string) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				ok, err := w.db.HeartbeatQueueClaim(id, token)
				if err != nil {
					log.Printf("[delivery] worker %d: queue claim heartbeat failed for entry %d: %v", w.id, id, err)
				} else if !ok {
					log.Printf("[delivery] worker %d: queue claim lost for entry %d; outcome will require reconciliation", w.id, id)
					return
				}
			}
		}
	}()
	return func() { close(stop); <-done }
}

func (w *Worker) transitionOwnedQueue(id int64, token, status string, attempts int, nextRetry time.Time, lastError string, smtpCode int, successDetail string) error {
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		err = w.db.TransitionOwnedQueueEntryWithCode(id, token, status, attempts, nextRetry, lastError, smtpCode, successDetail)
		if err == nil {
			return nil
		}
		if attempt < 3 {
			time.Sleep(time.Duration(attempt*50) * time.Millisecond)
		}
	}
	return err
}

func (w *Worker) logStatePersistenceFailure(entry *store.QueueEntry, intended string, err error) {
	metrics.IncDelivery("state_error")
	log.Printf("[delivery] CRITICAL: worker %d delivered/attempted queue entry %d but could not persist state %q: %v; inspect queue history before retrying because the outcome may require operator reconciliation",
		w.id, entry.ID, intended, err)
}

// isLocalRecipient checks whether the recipient's domain is configured here.
// Disabled hosted domains must still route locally: treating them as remote
// could leak queued mail to an external MX after an administrator disables one.
func (w *Worker) isLocalRecipient(rcpt string) (bool, error) {
	domain := parseRecipientDomain(rcpt)
	if domain == "" {
		return false, fmt.Errorf("%w: invalid recipient address %q", smtp.ErrInvalidEnvelopeAddress, rcpt)
	}
	var err error
	domain, err = idna.Lookup.ToASCII(domain)
	if err != nil || domain == "" {
		return false, fmt.Errorf("%w: invalid recipient domain %q", smtp.ErrInvalidEnvelopeAddress, rcpt)
	}
	domain = strings.ToLower(domain)

	hosted, err := w.db.GetDomainByName(domain)
	if err != nil {
		return false, fmt.Errorf("looking up local domain: %w", err)
	}
	return hosted != nil, nil
}

func queueReversePath(entry *store.QueueEntry) string {
	if entry.VERPBounceAddress != "" {
		return entry.VERPBounceAddress
	}
	return entry.MailFrom
}

// deliverLocal delivers a message directly to a local account's mailbox.
func (w *Worker) deliverLocal(entry *store.QueueEntry, messageWithARC []byte) error {
	return w.deliverLocalWithClaim(entry, "", messageWithARC)
}

func (w *Worker) deliverLocalClaimed(entry *store.QueueEntry, token string, messageWithARC []byte) error {
	return w.deliverLocalWithClaim(entry, token, messageWithARC)
}

func (w *Worker) deliverLocalWithClaim(entry *store.QueueEntry, token string, messageWithARC []byte) error {
	rcpt := entry.RcptTo
	if at := strings.LastIndexByte(rcpt, '@'); at >= 0 {
		domain, err := idna.Lookup.ToASCII(rcpt[at+1:])
		if err != nil || domain == "" {
			return fmt.Errorf("%w: invalid local recipient domain %q", smtp.ErrInvalidEnvelopeAddress, rcpt)
		}
		rcpt = rcpt[:at+1] + strings.ToLower(domain)
	}
	hostedDomain, err := w.db.GetDomainByName(parseRecipientDomain(rcpt))
	if err != nil {
		return fmt.Errorf("checking local recipient domain: %w", err)
	}
	if hostedDomain == nil || !hostedDomain.IsActive {
		return fmt.Errorf("%w: %s", errLocalDomainInactive, parseRecipientDomain(rcpt))
	}
	reversePath := queueReversePath(entry)

	account, err := w.db.GetDeliveryAccount(rcpt)
	if err != nil {
		return fmt.Errorf("account lookup for %s: %w", rcpt, err)
	}
	if account == nil {
		return fmt.Errorf("%w: %s", errLocalMailboxMissing, rcpt)
	}
	if !account.IsActive {
		return fmt.Errorf("%w: %s", errLocalMailboxInactive, rcpt)
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
	rawMessageWithReceived, err = smtp.FinalDeliveryReturnPath(rawMessageWithReceived, reversePath)
	if err != nil {
		return fmt.Errorf("setting local Return-Path: %w", err)
	}

	// Extract raw headers directly to preserve duplicate headers (like multiple ARC-* headers)
	// Don't use parsed.RawHeaders because parser loses duplicate header support
	var rawHeaders strings.Builder
	lines := strings.Split(string(rawMessageWithReceived), "\r\n")
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
		MailFrom:       reversePath,
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
	} else {
		return fmt.Errorf("account %s has no inbox folder", rcpt)
	}

	attachments := make([]store.IMAPAppendAttachment, 0, len(parsed.Attachments))
	for _, attachment := range parsed.Attachments {
		attachments = append(attachments, store.IMAPAppendAttachment{Filename: attachment.Filename, ContentType: attachment.ContentType, Data: attachment.Data})
	}
	var msgID int64
	if token != "" {
		msgID, err = w.db.SaveClaimedLocalDelivery(msg, attachments, entry.ID, token, entry.Attempts+1)
	} else {
		var ids []int64
		ids, err = w.db.SaveMessagesWithQueueAndAttachments([]*store.Message{msg}, nil, [][]store.IMAPAppendAttachment{attachments})
		if err == nil {
			msgID = ids[0]
		}
	}
	if err != nil {
		return fmt.Errorf("saving message for %s: %w", rcpt, err)
	}

	log.Printf("[delivery] local delivery: id=%d from=%s to=%s rawmessage_size=%d",
		msgID, entry.MailFrom, rcpt, len(rawMessageWithReceived))
	return nil
}

// parseRecipientDomain extracts the domain from an email address
func parseRecipientDomain(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at >= 0 && at < len(email)-1 {
		return email[at+1:]
	}
	return ""
}

// extractSMTPCode extracts SMTP reply code from error message.
// Example: "message rejected by host.com: 550 5.1.1 user unknown"
func extractSMTPCode(errMsg string) int {
	// This is only for the diagnostic code of persisted, pre-existing queue
	// failures. Live retry decisions use typed SMTPFailureCode instead.
	knownReply := strings.Contains(errMsg, "rejected by ") || strings.Contains(errMsg, "unexpected greeting from ") ||
		strings.Contains(errMsg, "EHLO rejected:") || strings.Contains(errMsg, "HELO rejected:") ||
		strings.Contains(errMsg, "invalid queued message") || strings.Contains(errMsg, "invalid envelope address") ||
		strings.Contains(errMsg, "SMTPUTF8 required") ||
		strings.Contains(errMsg, "8BITMIME required") || strings.Contains(errMsg, "recipient domain has no MX") ||
		strings.Contains(errMsg, "recipient domain does not accept mail")
	if !knownReply {
		return 0
	}
	if strings.Contains(errMsg, "invalid envelope address") {
		return 553
	}
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
	// Network and DNS errors have no SMTP code and should remain retryable.
	return 0
}

// isPermanentFailure follows SMTP reply classes. Unknown/network errors retry.
func isPermanentFailure(smtpCode int) bool {
	return smtpCode >= 500 && smtpCode < 600
}

// sendDSNReport sends a Delivery Status Notification (DSN) for a delivery failure.
// Only sends if DSN was requested via the NOTIFY parameter.
func (w *Worker) sendDSNReport(entry *store.QueueEntry, errorMsg string, smtpCode int) error {
	return w.sendRequestedDSN(entry, "failed", errorMsg, smtpCode)
}

func (w *Worker) processFinalDSNs() {
	entries, err := w.db.GetPendingFinalDSNs(10)
	if err != nil {
		log.Printf("[delivery] final DSN retry scan: %v", err)
		return
	}
	for _, entry := range entries {
		if entry.Status == "sent" {
			w.sendFinalDSNOrSchedule(entry, "delivered", "delivery completed", 250)
		} else {
			w.sendFinalDSNOrSchedule(entry, "failed", entry.LastError, extractSMTPCode(entry.LastError))
		}
	}
}

func (w *Worker) sendFinalDSNOrSchedule(entry *store.QueueEntry, action, detail string, smtpCode int) {
	if err := w.sendRequestedDSN(entry, action, detail, smtpCode); err != nil {
		attempts := entry.DSNAttempts + 1
		backoff := time.Minute * time.Duration(1<<min(attempts-1, 6))
		if err := w.db.ScheduleFinalDSNRetry(entry.ID, attempts, time.Now().UTC().Add(backoff)); err != nil {
			log.Printf("[delivery] persist final DSN retry for %d: %v", entry.ID, err)
		}
		log.Printf("[delivery] final DSN for queue %d deferred (attempt %d)", entry.ID, attempts)
	}
}

func (w *Worker) sendRequestedDSN(entry *store.QueueEntry, action, detail string, smtpCode int) error {
	if entry.MailFrom == "" {
		return nil
	}
	// No NOTIFY parameter requests the standard failure-only behavior; retain
	// its absence on the outbound SMTP envelope instead of synthesizing one.
	notify := entry.DSNNotify
	if notify == "" {
		notify = "FAILURE"
	}
	flag := map[string]string{"failed": "FAILURE", "delayed": "DELAY", "delivered": "SUCCESS"}[action]
	if flag == "" || !dsnNotifyContains(notify, flag) {
		return nil
	}
	if action == "delayed" && entry.DSNDelaySent {
		return nil
	}
	if action != "delayed" && entry.DSNSent {
		return nil
	}

	log.Printf("[delivery] sending %s DSN for %s (from %s)", action, entry.RcptTo, entry.MailFrom)

	// Import DSN reporting package
	dsnReport, err := reporting.BuildDSNMessageWithSender(
		w.cfg.Server.Hostname,
		w.cfg.Server.DSNSenderAddress(),
		entry.RcptTo,
		entry.OriginalRecipient,
		entry.MailFrom,
		action,
		detail,
		smtpCode,
		entry.DSNEnvID,
		entry.DSNRet,
		entry.RawMessage,
	)
	if err != nil {
		log.Printf("[delivery] failed to build DSN: %v", err)
		return err
	}

	// Send DSN as an inbound message to the sender's mailbox (reverse path)
	finalQueueID := int64(0)
	delayQueueID := int64(0)
	if action == "delayed" {
		delayQueueID = entry.ID
	} else {
		finalQueueID = entry.ID
	}
	outcome := "failed"
	if action == "delivered" {
		outcome = "sent"
	} else if entry.Status == "cancelled" {
		outcome = "cancelled"
	}
	if err := w.deliverDSN(entry.MailFrom, dsnReport, finalQueueID, delayQueueID, outcome); err != nil {
		if errors.Is(err, store.ErrDSNAlreadySent) {
			if action == "delayed" {
				entry.DSNDelaySent = true
			} else {
				entry.DSNSent = true
			}
			return nil
		}
		log.Printf("[delivery] failed to deliver DSN to %s: %v", entry.MailFrom, err)
		return err
	}

	// --- Record VERP bounce only for final failure. ---
	if action == "failed" && w.cfg.Delivery.IsVERPEnabled() {
		// Extract bounce type from SMTP code (4xx = temporary, 5xx = permanent)
		bounceType := "unknown"
		if smtpCode >= 500 && smtpCode < 600 {
			bounceType = "permanent"
		} else if smtpCode >= 400 && smtpCode < 500 {
			bounceType = "temporary"
		}

		// Use VERP bounce address if available, otherwise use original sender
		bounceAddr := entry.VERPBounceAddress
		if bounceAddr == "" {
			bounceAddr = entry.MailFrom
		}

		log.Printf("[delivery] [verp] recording bounce - recipient=%s sender=%s bounce_addr=%s type=%s code=%d",
			entry.RcptTo, entry.MailFrom, bounceAddr, bounceType, smtpCode)

		if err := w.db.RecordVERPBounce(entry.RcptTo, entry.MailFrom, bounceAddr, bounceType, smtpCode, detail); err != nil {
			log.Printf("[delivery] [verp] error recording bounce: %v", err)
		}
	}

	if action == "delayed" {
		entry.DSNDelaySent = true
	} else {
		entry.DSNSent = true
	}

	return nil
}

func dsnNotifyContains(value, wanted string) bool {
	for _, flag := range strings.Split(strings.ToUpper(value), ",") {
		if strings.TrimSpace(flag) == wanted {
			return true
		}
	}
	return false
}

// deliverDSN stores a DSN report message in the sender's mailbox.
func (w *Worker) deliverDSN(senderEmail string, dsnReport string, finalQueueID, delayQueueID int64, outcome string) error {
	account, err := w.db.GetDeliveryAccount(senderEmail)
	if err != nil {
		return fmt.Errorf("resolving DSN destination %s: %w", senderEmail, err)
	}
	if account == nil || !account.IsActive {
		return fmt.Errorf("active mailbox not found for DSN: %s", senderEmail)
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
	rawDSN, err := smtp.FinalDeliveryReturnPath(append([]byte(receivedHeader), dsnReport...), "")
	if err != nil {
		return fmt.Errorf("setting DSN Return-Path: %w", err)
	}
	headerEnd := strings.Index(string(rawDSN), "\r\n\r\n")
	if headerEnd < 0 {
		return fmt.Errorf("DSN has no header/body separator")
	}

	msg := &store.Message{
		AccountID:  account.ID,
		MessageID:  fmt.Sprintf("%d@%s", time.Now().UnixNano(), w.cfg.Server.Hostname),
		Direction:  "inbound",
		MailFrom:   "",
		RcptTo:     senderEmail,
		FromAddr:   w.cfg.Server.DSNSenderAddress(),
		ToAddr:     senderEmail,
		Subject:    parsed.Subject,
		TextBody:   parsed.TextBody,
		HTMLBody:   parsed.HTMLBody,
		RawHeaders: string(rawDSN[:headerEnd+2]),
		RawMessage: rawDSN,
		Size:       int64(len(rawDSN)),
		IsRead:     false,
		ReceivedAt: time.Now(),
	}

	// Store in Inbox
	inboxFolder, err := w.db.GetFolderByType(account.ID, "inbox")
	if err != nil {
		return fmt.Errorf("getting DSN inbox folder: %w", err)
	}
	if inboxFolder == nil {
		return fmt.Errorf("account %s has no inbox folder for DSN", senderEmail)
	}
	msg.FolderID = &inboxFolder.ID

	if finalQueueID != 0 {
		_, err = w.db.SaveFinalDSNMessage(msg, finalQueueID, outcome)
	} else if delayQueueID != 0 {
		_, err = w.db.SaveDelayDSNMessage(msg, delayQueueID)
	} else {
		_, err = w.db.SaveMessage(msg)
	}
	if err != nil {
		return fmt.Errorf("saving DSN message: %w", err)
	}

	return nil
}

// buildDSNMessage constructs an RFC 3464 DSN report message.
func buildDSNMessage(
	reportingMTA string,
	failedRecipient string,
	originalRecipient string,
	originalSender string,
	action string,
	diagnosticText string,
	smtpCode int,
	envID string,
	returnType string,
	originalMessage []byte,
) (string, error) {
	return reporting.BuildDSNMessage(reportingMTA, failedRecipient, originalRecipient, originalSender, action, diagnosticText, smtpCode, envID, returnType, originalMessage)
}
