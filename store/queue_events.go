package store

import (
	"fmt"
	"strings"
	"time"
)

type QueueEvent struct {
	ID        int64
	QueueID   int64
	Type      string
	Attempt   int
	SMTPCode  int
	Detail    string
	CreatedAt time.Time
}

func appendQueueEvent(exec sqlExecutor, id int64, eventType string, attempt, smtpCode int, detail string) error {
	detail = strings.ToValidUTF8(strings.TrimSpace(detail), "�")
	if len(detail) > 500 {
		detail = detail[:500]
		detail = strings.ToValidUTF8(detail, "�")
	}
	_, err := exec.Exec(`INSERT INTO outbound_queue_events (queue_id, event_type, attempt, smtp_code, detail)
		VALUES (?, ?, ?, ?, ?)`, id, eventType, attempt, smtpCode, detail)
	return err
}

// ListQueueEvents returns a bounded, newest-first history without message data.
func (db *DB) ListQueueEvents(id int64, limit int) ([]QueueEvent, error) {
	if id <= 0 {
		return nil, fmt.Errorf("invalid queue id")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := db.Query(`SELECT id, queue_id, event_type, attempt, smtp_code, detail, created_at
		FROM outbound_queue_events WHERE queue_id = ? ORDER BY id DESC LIMIT ?`, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []QueueEvent
	for rows.Next() {
		var e QueueEvent
		if err := rows.Scan(&e.ID, &e.QueueID, &e.Type, &e.Attempt, &e.SMTPCode, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
