package delivery

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

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
	if w.isLocalRecipient(entry.RcptTo) {
		deliveryErr = w.deliverLocal(entry)
	} else {
		deliveryErr = smtp.SendMail(
			entry.MailFrom,
			entry.RcptTo,
			entry.RawMessage,
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
func (w *Worker) deliverLocal(entry *store.QueueEntry) error {
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

	// Parse the message
	parsed, err := parser.Parse(entry.RawMessage)
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
	rawMessageWithReceived := append([]byte(receivedHeader), entry.RawMessage...)

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
		RawHeaders:     parsed.RawHeaders,
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

	log.Printf("[delivery] local delivery: id=%d from=%s to=%s subject=%s",
		msgID, entry.MailFrom, rcpt, parsed.Subject)
	return nil
}
