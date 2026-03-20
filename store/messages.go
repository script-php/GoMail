package store

import (
	"database/sql"
	"fmt"
	"time"
)

// --- Message CRUD ---

// SaveMessage inserts a new message into the database.
func (db *DB) SaveMessage(m *Message) (int64, error) {
	result, err := db.Exec(`
		INSERT INTO messages (
			message_id, direction, mail_from, rcpt_to, from_addr, to_addr,
			cc_addr, reply_to, subject, text_body, html_body, raw_headers,
			raw_message, size, has_attachments, is_read, is_starred,
			spf_result, dkim_result, dmarc_result, auth_results, received_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.MessageID, m.Direction, m.MailFrom, m.RcptTo, m.FromAddr, m.ToAddr,
		m.CcAddr, m.ReplyTo, m.Subject, m.TextBody, m.HTMLBody, m.RawHeaders,
		m.RawMessage, m.Size, boolToInt(m.HasAttachments), boolToInt(m.IsRead),
		boolToInt(m.IsStarred), m.SPFResult, m.DKIMResult, m.DMARCResult,
		m.AuthResults, m.ReceivedAt,
	)
	if err != nil {
		return 0, fmt.Errorf("saving message: %w", err)
	}
	return result.LastInsertId()
}

// GetMessage retrieves a single message by ID.
func (db *DB) GetMessage(id int64) (*Message, error) {
	m := &Message{}
	var hasAttach, isRead, isStarred, isDeleted int
	err := db.QueryRow(`
		SELECT id, message_id, direction, mail_from, rcpt_to, from_addr, to_addr,
			cc_addr, reply_to, subject, text_body, html_body, raw_headers,
			size, has_attachments, is_read, is_starred, is_deleted,
			spf_result, dkim_result, dmarc_result, auth_results, received_at, created_at
		FROM messages WHERE id = ?`, id).Scan(
		&m.ID, &m.MessageID, &m.Direction, &m.MailFrom, &m.RcptTo, &m.FromAddr,
		&m.ToAddr, &m.CcAddr, &m.ReplyTo, &m.Subject, &m.TextBody, &m.HTMLBody,
		&m.RawHeaders, &m.Size, &hasAttach, &isRead, &isStarred, &isDeleted,
		&m.SPFResult, &m.DKIMResult, &m.DMARCResult, &m.AuthResults,
		&m.ReceivedAt, &m.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting message %d: %w", id, err)
	}
	m.HasAttachments = hasAttach == 1
	m.IsRead = isRead == 1
	m.IsStarred = isStarred == 1
	m.IsDeleted = isDeleted == 1
	return m, nil
}

// ListMessages returns messages for the given direction (inbox = "inbound", sent = "outbound").
// Results are paginated with limit/offset, most recent first.
func (db *DB) ListMessages(direction string, limit, offset int) ([]*Message, error) {
	rows, err := db.Query(`
		SELECT id, message_id, direction, mail_from, rcpt_to, from_addr, to_addr,
			subject, size, has_attachments, is_read, is_starred,
			spf_result, dkim_result, dmarc_result, received_at
		FROM messages
		WHERE direction = ? AND is_deleted = 0
		ORDER BY received_at DESC
		LIMIT ? OFFSET ?`, direction, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("listing messages: %w", err)
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		m := &Message{}
		var hasAttach, isRead, isStarred int
		if err := rows.Scan(
			&m.ID, &m.MessageID, &m.Direction, &m.MailFrom, &m.RcptTo,
			&m.FromAddr, &m.ToAddr, &m.Subject, &m.Size,
			&hasAttach, &isRead, &isStarred,
			&m.SPFResult, &m.DKIMResult, &m.DMARCResult, &m.ReceivedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning message row: %w", err)
		}
		m.HasAttachments = hasAttach == 1
		m.IsRead = isRead == 1
		m.IsStarred = isStarred == 1
		messages = append(messages, m)
	}
	return messages, rows.Err()
}

// CountMessages returns the count of non-deleted messages for a direction.
func (db *DB) CountMessages(direction string) (int, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM messages WHERE direction = ? AND is_deleted = 0`,
		direction).Scan(&count)
	return count, err
}

// CountUnread returns the count of unread, non-deleted inbound messages.
func (db *DB) CountUnread() (int, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM messages WHERE direction = 'inbound' AND is_read = 0 AND is_deleted = 0`,
	).Scan(&count)
	return count, err
}

// MarkRead marks a message as read.
func (db *DB) MarkRead(id int64) error {
	_, err := db.Exec(`UPDATE messages SET is_read = 1 WHERE id = ?`, id)
	return err
}

// MarkStarred toggles the starred status.
func (db *DB) MarkStarred(id int64, starred bool) error {
	_, err := db.Exec(`UPDATE messages SET is_starred = ? WHERE id = ?`, boolToInt(starred), id)
	return err
}

// DeleteMessage soft-deletes a message.
func (db *DB) DeleteMessage(id int64) error {
	_, err := db.Exec(`UPDATE messages SET is_deleted = 1 WHERE id = ?`, id)
	return err
}

// --- Attachment CRUD ---

// SaveAttachment inserts an attachment record.
func (db *DB) SaveAttachment(a *Attachment) (int64, error) {
	result, err := db.Exec(`
		INSERT INTO attachments (message_id, filename, content_type, size, storage_path)
		VALUES (?, ?, ?, ?, ?)`,
		a.MessageID, a.Filename, a.ContentType, a.Size, a.StoragePath,
	)
	if err != nil {
		return 0, fmt.Errorf("saving attachment: %w", err)
	}
	return result.LastInsertId()
}

// GetAttachments returns all attachments for a message.
func (db *DB) GetAttachments(messageID int64) ([]*Attachment, error) {
	rows, err := db.Query(`
		SELECT id, message_id, filename, content_type, size, storage_path, created_at
		FROM attachments WHERE message_id = ?`, messageID)
	if err != nil {
		return nil, fmt.Errorf("getting attachments: %w", err)
	}
	defer rows.Close()

	var attachments []*Attachment
	for rows.Next() {
		a := &Attachment{}
		if err := rows.Scan(&a.ID, &a.MessageID, &a.Filename, &a.ContentType,
			&a.Size, &a.StoragePath, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning attachment row: %w", err)
		}
		attachments = append(attachments, a)
	}
	return attachments, rows.Err()
}

// --- Queue CRUD ---

// EnqueueMessage adds a message to the outbound delivery queue.
func (db *DB) EnqueueMessage(q *QueueEntry) (int64, error) {
	result, err := db.Exec(`
		INSERT INTO outbound_queue (message_id, mail_from, rcpt_to, raw_message, max_attempts, next_retry)
		VALUES (?, ?, ?, ?, ?, ?)`,
		q.MessageID, q.MailFrom, q.RcptTo, q.RawMessage, q.MaxAttempts, q.NextRetry,
	)
	if err != nil {
		return 0, fmt.Errorf("enqueueing message: %w", err)
	}
	return result.LastInsertId()
}

// GetPendingQueue returns queue entries that are ready for delivery attempt.
func (db *DB) GetPendingQueue(limit int) ([]*QueueEntry, error) {
	rows, err := db.Query(`
		SELECT id, message_id, mail_from, rcpt_to, raw_message, attempts, max_attempts,
			next_retry, last_error, status, created_at, updated_at
		FROM outbound_queue
		WHERE status = 'pending' AND next_retry <= datetime('now')
		ORDER BY next_retry ASC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("reading queue: %w", err)
	}
	defer rows.Close()

	var entries []*QueueEntry
	for rows.Next() {
		q := &QueueEntry{}
		if err := rows.Scan(&q.ID, &q.MessageID, &q.MailFrom, &q.RcptTo,
			&q.RawMessage, &q.Attempts, &q.MaxAttempts, &q.NextRetry,
			&q.LastError, &q.Status, &q.CreatedAt, &q.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning queue row: %w", err)
		}
		entries = append(entries, q)
	}
	return entries, rows.Err()
}

// UpdateQueueEntry updates a queue entry after a delivery attempt.
func (db *DB) UpdateQueueEntry(id int64, status string, attempts int, nextRetry time.Time, lastError string) error {
	_, err := db.Exec(`
		UPDATE outbound_queue
		SET status = ?, attempts = ?, next_retry = ?, last_error = ?, updated_at = datetime('now')
		WHERE id = ?`,
		status, attempts, nextRetry, lastError, id,
	)
	return err
}

// DeleteQueueEntry removes a completed/failed entry from the queue.
func (db *DB) DeleteQueueEntry(id int64) error {
	_, err := db.Exec(`DELETE FROM outbound_queue WHERE id = ?`, id)
	return err
}

// --- Session CRUD ---

// SaveSession stores a web session.
func (db *DB) SaveSession(token string, data string, expiresAt time.Time) error {
	_, err := db.Exec(`
		INSERT OR REPLACE INTO sessions (token, data, expires_at)
		VALUES (?, ?, ?)`, token, data, expiresAt)
	return err
}

// GetSession retrieves session data if not expired.
func (db *DB) GetSession(token string) (string, error) {
	var data string
	err := db.QueryRow(`
		SELECT data FROM sessions WHERE token = ? AND expires_at > datetime('now')`,
		token).Scan(&data)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return data, err
}

// DeleteSession removes a session.
func (db *DB) DeleteSession(token string) error {
	_, err := db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	return err
}

// CleanExpiredSessions removes all expired sessions.
func (db *DB) CleanExpiredSessions() error {
	_, err := db.Exec(`DELETE FROM sessions WHERE expires_at <= datetime('now')`)
	return err
}

// --- Helpers ---

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
