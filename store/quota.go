package store

import (
	"database/sql"
	"errors"
	"fmt"
)

var ErrQuotaExceeded = errors.New("mailbox quota exceeded")

func prepareMessageSize(message *Message) {
	if message.Size > 0 {
		return
	}
	if len(message.RawMessage) > 0 {
		message.Size = int64(len(message.RawMessage))
		return
	}
	message.Size = int64(len(message.RawHeaders) + len(message.TextBody) + len(message.HTMLBody))
}

func reserveMailboxBytes(tx *sql.Tx, accountID, bytes int64) error {
	if accountID == 0 || bytes <= 0 {
		return nil
	}
	result, err := tx.Exec(`UPDATE accounts
		SET mailbox_used_bytes = mailbox_used_bytes + ?
		WHERE id = ? AND is_active = 1
		  AND (quota_bytes = 0 OR mailbox_used_bytes + ? <= quota_bytes)`, bytes, accountID, bytes)
	if err != nil {
		return fmt.Errorf("reserving mailbox quota: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		var exists int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM accounts WHERE id = ? AND is_active = 1`, accountID).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return sql.ErrNoRows
		}
		return ErrQuotaExceeded
	}
	return nil
}

func releaseMailboxBytes(tx *sql.Tx, accountID, bytes int64) error {
	if accountID == 0 || bytes <= 0 {
		return nil
	}
	_, err := tx.Exec(`UPDATE accounts SET mailbox_used_bytes = CASE
		WHEN mailbox_used_bytes >= ? THEN mailbox_used_bytes - ? ELSE 0 END
		WHERE id = ?`, bytes, bytes, accountID)
	return err
}

func (db *DB) MailboxUsage(accountID int64) (used, quota int64, err error) {
	err = db.QueryRow(`SELECT mailbox_used_bytes, quota_bytes FROM accounts WHERE id = ?`, accountID).Scan(&used, &quota)
	return
}
