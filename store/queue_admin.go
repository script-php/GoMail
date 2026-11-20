package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const AdminQueuePageSize = 50
const adminCancellationReason = "delivery cancelled by administrator"

// QueueAdminEntry intentionally omits raw_message so the administration page
// cannot expose message bodies or attachments.
type QueueAdminEntry struct {
	ID          int64
	MessageID   *int64
	MailFrom    string
	RcptTo      string
	Attempts    int
	MaxAttempts int
	NextRetry   time.Time
	LastError   string
	Status      string
	DSNSent     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type QueueAdminPage struct {
	Entries     []QueueAdminEntry
	Total       int
	Page        int
	TotalPages  int
	StatusCount map[string]int64
}

func validQueueStatus(status string) bool {
	switch status {
	case "pending", "sending", "uncertain", "sent", "failed", "cancelled":
		return true
	default:
		return false
	}
}

// ListQueueAdmin returns bounded queue metadata. Raw messages are never read.
func (db *DB) ListQueueAdmin(status, query string, page int) (QueueAdminPage, error) {
	result := QueueAdminPage{Page: page, StatusCount: map[string]int64{}}
	if result.Page < 1 {
		result.Page = 1
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "" && status != "all" && !validQueueStatus(status) {
		return result, fmt.Errorf("invalid queue status")
	}

	countRows, err := db.Query(`SELECT status, COUNT(*) FROM outbound_queue GROUP BY status`)
	if err != nil {
		return result, fmt.Errorf("counting queue states: %w", err)
	}
	for countRows.Next() {
		var name string
		var count int64
		if err := countRows.Scan(&name, &count); err != nil {
			countRows.Close()
			return result, err
		}
		result.StatusCount[name] = count
	}
	if err := countRows.Close(); err != nil {
		return result, err
	}

	where := []string{"1 = 1"}
	args := []interface{}{}
	if status != "" && status != "all" {
		where = append(where, "status = ?")
		args = append(args, status)
	}
	if query = strings.TrimSpace(query); query != "" {
		where = append(where, "(LOWER(mail_from) LIKE ? ESCAPE '!' OR LOWER(rcpt_to) LIKE ? ESCAPE '!')")
		needle := "%" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(strings.ToLower(query)) + "%"
		args = append(args, needle, needle)
	}
	clause := strings.Join(where, " AND ")
	if err := db.QueryRow(`SELECT COUNT(*) FROM outbound_queue WHERE `+clause, args...).Scan(&result.Total); err != nil {
		return result, fmt.Errorf("counting filtered queue: %w", err)
	}
	result.TotalPages = (result.Total + AdminQueuePageSize - 1) / AdminQueuePageSize
	if result.TotalPages == 0 {
		result.Page = 1
	}
	if result.TotalPages > 0 && result.Page > result.TotalPages {
		result.Page = result.TotalPages
	}
	args = append(args, AdminQueuePageSize, (result.Page-1)*AdminQueuePageSize)
	rows, err := db.Query(`SELECT id, message_id, mail_from, rcpt_to, attempts, max_attempts,
		next_retry, last_error, status, dsn_sent, created_at, updated_at
		FROM outbound_queue WHERE `+clause+`
		ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return result, fmt.Errorf("listing queue: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var entry QueueAdminEntry
		var dsnSent int
		if err := rows.Scan(&entry.ID, &entry.MessageID, &entry.MailFrom, &entry.RcptTo,
			&entry.Attempts, &entry.MaxAttempts, &entry.NextRetry, &entry.LastError,
			&entry.Status, &dsnSent, &entry.CreatedAt, &entry.UpdatedAt); err != nil {
			return result, err
		}
		entry.DSNSent = dsnSent != 0
		if len(entry.LastError) > 500 {
			entry.LastError = entry.LastError[:500] + "…"
		}
		result.Entries = append(result.Entries, entry)
	}
	return result, rows.Err()
}

func (db *DB) queueAdminTransition(id int64, from []string, to string, eventType string, resetAttempts bool) (bool, error) {
	if id <= 0 || !validQueueStatus(to) || len(from) == 0 {
		return false, fmt.Errorf("invalid queue transition")
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(from)), ",")
	set := "status = ?, claim_token = '', next_retry = ?, last_error = '', updated_at = CURRENT_TIMESTAMP"
	if eventType == "admin_cancel" {
		set = "status = ?, claim_token = '', next_retry = ?, last_error = '" + adminCancellationReason + "', updated_at = CURRENT_TIMESTAMP"
	}
	if resetAttempts {
		set += ", attempts = 0"
	}
	args := []interface{}{to, databaseTime(time.Now().UTC())}
	args = append(args, id)
	for _, status := range from {
		args = append(args, status)
	}
	tx, err := db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE outbound_queue SET `+set+` WHERE id = ? AND status IN (`+placeholders+`)`, args...)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil || affected != 1 {
		return false, err
	}
	var attempt int
	if err := tx.QueryRow(`SELECT attempts FROM outbound_queue WHERE id = ?`, id).Scan(&attempt); err != nil {
		return false, err
	}
	if err := appendQueueEvent(tx, id, eventType, attempt, 0, "operator decision"); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// RetryQueueEntry requeues a terminal failed entry. DSN state is preserved so
// an operator retry cannot emit duplicate failure or delay notifications.
func (db *DB) RetryQueueEntry(id int64) (bool, error) {
	return db.queueAdminTransition(id, []string{"failed"}, "pending", "admin_retry_failed", true)
}

// CancelQueueEntry cancels only entries not currently owned by a worker.
func (db *DB) CancelQueueEntry(id int64) (bool, error) {
	return db.queueAdminTransition(id, []string{"pending", "failed"}, "cancelled", "admin_cancel", false)
}

// RecoverStaleQueueEntry quarantines one abandoned claim for operator review.
func (db *DB) RecoverStaleQueueEntry(id int64) (bool, error) {
	tx, err := db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE outbound_queue SET status = 'uncertain',
		last_error = 'delivery outcome unknown after worker heartbeat expired; check recipient and delivery logs before resolving', updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status = 'sending' AND updated_at < ?`,
		id, databaseTime(time.Now().UTC().Add(-30*time.Minute)))
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil || affected != 1 {
		return false, err
	}
	var attempt int
	if err := tx.QueryRow(`SELECT attempts FROM outbound_queue WHERE id = ?`, id).Scan(&attempt); err != nil {
		return false, err
	}
	if err := appendQueueEvent(tx, id, "outcome_uncertain", attempt+1, 0, "worker heartbeat expired; delivery outcome unknown"); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// ResolveUncertainQueueEntry requires an explicit operator decision. A retry
// can still duplicate a message that the remote server accepted before a crash.
func (db *DB) ResolveUncertainQueueEntry(id int64, resolution string) (bool, error) {
	switch resolution {
	case "retry":
		return db.queueAdminTransition(id, []string{"uncertain"}, "pending", "admin_retry_uncertain", true)
	case "delivered":
		return db.queueAdminTransition(id, []string{"uncertain"}, "sent", "admin_mark_delivered", false)
	case "cancel":
		return db.queueAdminTransition(id, []string{"uncertain"}, "cancelled", "admin_cancel_uncertain", false)
	default:
		return false, fmt.Errorf("invalid uncertain queue resolution")
	}
}

// QueueEntryStatus is used to distinguish a safe compare-and-set miss from a
// missing record in admin feedback.
func (db *DB) QueueEntryStatus(id int64) (string, error) {
	var status string
	err := db.QueryRow(`SELECT status FROM outbound_queue WHERE id = ?`, id).Scan(&status)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return status, err
}
