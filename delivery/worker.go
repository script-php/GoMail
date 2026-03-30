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
		deliveryErr = smtp.SendMail(
			entry.MailFrom,
			entry.RcptTo,
			messageWithARC,
			w.cfg.Server.Hostname,
			w.tlsCfg,
		)
	}

	if deliveryErr != nil {
		entry.Attempts++
		if entry.Attempts >= entry.MaxAttempts {
			log.Printf("[delivery] worker %d: permanent failure for %s->%s: %v",
				w.id, entry.MailFrom, entry.RcptTo, deliveryErr)
			w.db.UpdateQueueEntry(entry.ID, "failed", entry.Attempts, time.Now().UTC(), deliveryErr.Error())
		} else {
			nextRetry := w.schedule.NextRetry(entry.Attempts)
			log.Printf("[delivery] worker %d: temporary failure for %s->%s (attempt %d/%d), retry at %s: %v",
				w.id, entry.MailFrom, entry.RcptTo, entry.Attempts, entry.MaxAttempts, nextRetry.Format(time.RFC3339), deliveryErr)
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
		"pass",   // SPF (originating from GoMail, trusted)
		"pass",   // DKIM (will sign this message)
		"pass",   // DMARC
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


