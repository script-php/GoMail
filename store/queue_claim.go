package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// ClaimQueueEntry assigns a unique delivery attempt to one worker. The SQL
// condition arbitrates claims across processes and database connections.
func (db *DB) ClaimQueueEntry(id int64) (string, bool, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", false, fmt.Errorf("creating queue claim: %w", err)
	}
	token := hex.EncodeToString(bytes[:])
	tx, err := db.Begin()
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE outbound_queue SET status = 'sending', claim_token = ?,
		updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending' AND next_retry <= CURRENT_TIMESTAMP`, token, id)
	if err != nil {
		return "", false, fmt.Errorf("claiming queue entry: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return "", false, err
	}
	var attempt int
	if err := tx.QueryRow(`SELECT attempts FROM outbound_queue WHERE id = ?`, id).Scan(&attempt); err != nil {
		return "", false, err
	}
	if err := appendQueueEvent(tx, id, "attempt_started", attempt+1, 0, "worker claimed delivery"); err != nil {
		return "", false, err
	}
	if err := tx.Commit(); err != nil {
		return "", false, err
	}
	return token, true, nil
}

// HeartbeatQueueClaim keeps active deliveries out of stale recovery.
func (db *DB) HeartbeatQueueClaim(id int64, token string) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("missing queue claim token")
	}
	result, err := db.Exec(`UPDATE outbound_queue SET updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status = 'sending' AND claim_token = ?`, id, token)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

// TransitionOwnedQueueEntry cannot overwrite a later retry or recovery claim.
// An original worker may still report an outcome from an uncertain entry until
// an operator explicitly resolves it and clears its token.
func (db *DB) TransitionOwnedQueueEntry(id int64, token, status string, attempts int, nextRetry time.Time, lastError string) error {
	return db.TransitionOwnedQueueEntryWithCode(id, token, status, attempts, nextRetry, lastError, 0, "")
}

func (db *DB) TransitionOwnedQueueEntryWithCode(id int64, token, status string, attempts int, nextRetry time.Time, lastError string, smtpCode int, successDetail string) error {
	if token == "" || (status != "pending" && status != "failed" && status != "sent" && status != "cancelled") {
		return fmt.Errorf("invalid owned queue transition")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE outbound_queue SET status = ?, claim_token = '',
		attempts = ?, next_retry = ?, last_error = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status IN ('sending', 'uncertain') AND claim_token = ?`,
		status, attempts, databaseTime(nextRetry), lastError, id, token)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("queue entry %d claim changed before %s transition", id, status)
	}
	eventType := "temporary_failure"
	detail := lastError
	if status == "failed" {
		eventType = "final_failure"
	}
	if status == "sent" {
		eventType, detail = "delivery_succeeded", successDetail
	}
	if status == "cancelled" {
		eventType = "sender_inactive"
	}
	if err := appendQueueEvent(tx, id, eventType, attempts, smtpCode, detail); err != nil {
		return err
	}
	return tx.Commit()
}
