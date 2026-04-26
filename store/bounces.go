package store

import (
	"fmt"
	"log"
	"time"
)

// VERPBounce represents a tracked bounce from a VERP address.
type VERPBounce struct {
	ID                int64     `json:"id"`
	OriginalRecipient string    `json:"original_recipient"`
	SenderEmail       string    `json:"sender_email"`
	BounceAddress     string    `json:"bounce_address"`
	BounceType        string    `json:"bounce_type"` // permanent, temporary, unknown
	BounceCode        int       `json:"bounce_code"`
	BounceReason      string    `json:"bounce_reason"`
	QueueEntryID      *int64    `json:"queue_entry_id,omitempty"`
	BounceReceivedAt  time.Time `json:"bounce_received_at"`
	RecordedAt        time.Time `json:"recorded_at"`
}

// RecordVERPBounce logs a bounce tracked via VERP.
func (db *DB) RecordVERPBounce(originalRecipient, senderEmail, bounceAddress string, bounceType string, bounceCode int, bounceReason string) error {
	log.Printf("[verp] recording bounce for %s (sender: %s, type: %s, code: %d)", originalRecipient, senderEmail, bounceType, bounceCode)

	result, err := db.Exec(`
		INSERT INTO verp_bounces (original_recipient, sender_email, bounce_address, bounce_type, bounce_code, bounce_reason)
		VALUES (?, ?, ?, ?, ?, ?)`,
		originalRecipient, senderEmail, bounceAddress, bounceType, bounceCode, bounceReason,
	)
	if err != nil {
		return fmt.Errorf("recording VERP bounce: %w", err)
	}

	id, _ := result.LastInsertId()
	log.Printf("[verp] bounce recorded with ID %d", id)
	return nil
}

// GetVERPBounceStats returns bounce statistics for a sender/recipient combination.
func (db *DB) GetVERPBounceStats(senderEmail string, daysBack int) (map[string]int, error) {
	cutoff := time.Now().AddDate(0, 0, -daysBack)

	rows, err := db.Query(`
		SELECT original_recipient, COUNT(*) as count
		FROM verp_bounces
		WHERE sender_email = ? AND bounce_received_at >= ?
		GROUP BY original_recipient
		ORDER BY count DESC`,
		senderEmail, sqliteTime(cutoff),
	)
	if err != nil {
		return nil, fmt.Errorf("querying VERP bounce stats: %w", err)
	}
	defer rows.Close()

	stats := make(map[string]int)
	for rows.Next() {
		var recipient string
		var count int
		if err := rows.Scan(&recipient, &count); err != nil {
			return nil, fmt.Errorf("scanning bounce count: %w", err)
		}
		stats[recipient] = count
	}
	return stats, rows.Err()
}

// ListVERPBounces lists recent bounces, optionally filtered by sender or recipient.
func (db *DB) ListVERPBounces(senderEmail string, limit int) ([]*VERPBounce, error) {
	query := `
		SELECT id, original_recipient, sender_email, bounce_address, bounce_type, bounce_code, bounce_reason, queue_entry_id, bounce_received_at, recorded_at
		FROM verp_bounces`

	var args []interface{}
	if senderEmail != "" {
		query += ` WHERE sender_email = ?`
		args = append(args, senderEmail)
	}

	query += ` ORDER BY bounce_received_at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying VERP bounces: %w", err)
	}
	defer rows.Close()

	var bounces []*VERPBounce
	for rows.Next() {
		b := &VERPBounce{}
		if err := rows.Scan(&b.ID, &b.OriginalRecipient, &b.SenderEmail, &b.BounceAddress, &b.BounceType, &b.BounceCode, &b.BounceReason, &b.QueueEntryID, &b.BounceReceivedAt, &b.RecordedAt); err != nil {
			return nil, fmt.Errorf("scanning bounce row: %w", err)
		}
		bounces = append(bounces, b)
	}
	return bounces, rows.Err()
}

// CleanupOldVERPBounces removes bounce records older than specified days.
func (db *DB) CleanupOldVERPBounces(daysOld int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -daysOld)

	result, err := db.Exec(`
		DELETE FROM verp_bounces
		WHERE bounce_received_at < ?`,
		sqliteTime(cutoff),
	)
	if err != nil {
		return 0, fmt.Errorf("cleaning up old VERP bounces: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows > 0 {
		log.Printf("[verp] cleaned up %d old bounce records", rows)
	}
	return rows, nil
}
