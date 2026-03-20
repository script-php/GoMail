package delivery

import (
	"crypto/tls"
	"log"
	"sync"
	"time"

	"gomail/config"
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
}

// Pool manages a group of delivery workers.
type Pool struct {
	workers []*Worker
	db      *store.DB
	cfg     *config.Config
	tlsCfg  *tls.Config
	quit    chan struct{}
	wg      sync.WaitGroup
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
	// Fetch one pending entry
	entries, err := w.db.GetPendingQueue(1)
	if err != nil {
		log.Printf("[delivery] worker %d: queue read error: %v", w.id, err)
		return
	}

	for _, entry := range entries {
		// Mark as sending
		w.db.UpdateQueueEntry(entry.ID, "sending", entry.Attempts, entry.NextRetry, "")

		// Attempt delivery
		err := smtp.SendMail(
			entry.MailFrom,
			entry.RcptTo,
			entry.RawMessage,
			w.cfg.Server.Hostname,
			w.tlsCfg,
		)

		if err != nil {
			entry.Attempts++
			if entry.Attempts >= entry.MaxAttempts {
				// Permanently failed
				log.Printf("[delivery] worker %d: permanent failure for %s->%s: %v",
					w.id, entry.MailFrom, entry.RcptTo, err)
				w.db.UpdateQueueEntry(entry.ID, "failed", entry.Attempts, time.Now(), err.Error())
			} else {
				// Schedule retry
				nextRetry := w.schedule.NextRetry(entry.Attempts)
				log.Printf("[delivery] worker %d: temporary failure for %s->%s (attempt %d/%d), retry at %s: %v",
					w.id, entry.MailFrom, entry.RcptTo, entry.Attempts, entry.MaxAttempts, nextRetry.Format(time.RFC3339), err)
				w.db.UpdateQueueEntry(entry.ID, "pending", entry.Attempts, nextRetry, err.Error())
			}
		} else {
			// Success
			log.Printf("[delivery] worker %d: delivered %s->%s", w.id, entry.MailFrom, entry.RcptTo)
			w.db.UpdateQueueEntry(entry.ID, "sent", entry.Attempts+1, time.Now(), "")
		}
	}
}
