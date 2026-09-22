package store

import "fmt"

// POP3Message is the immutable snapshot exposed during one POP3 maildrop session.
type POP3Message struct {
	ID         int64
	RawMessage []byte
}

// ListPOP3Messages returns the account's current Inbox maildrop in stable ID order.
func (db *DB) ListPOP3Messages(accountID int64) ([]POP3Message, error) {
	rows, err := db.Query(`
		SELECT m.id, m.raw_message
		FROM messages m
		JOIN folders f ON f.id = m.folder_id
		WHERE m.account_id = ? AND f.account_id = ? AND f.folder_type = 'inbox'
		  AND m.direction = 'inbound' AND m.is_deleted = 0
		ORDER BY m.id`, accountID, accountID)
	if err != nil {
		return nil, fmt.Errorf("listing POP3 maildrop: %w", err)
	}
	defer rows.Close()

	var messages []POP3Message
	for rows.Next() {
		var message POP3Message
		if err := rows.Scan(&message.ID, &message.RawMessage); err != nil {
			return nil, fmt.Errorf("scanning POP3 maildrop: %w", err)
		}
		messages = append(messages, message)
	}
	return messages, rows.Err()
}

// DeletePOP3Messages atomically validates ownership and moves selected Inbox
// messages to Trash. POP3 calls this only after a successful QUIT.
func (db *DB) DeletePOP3Messages(accountID int64, messageIDs []int64) error {
	if len(messageIDs) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var inboxID, trashID int64
	if err := tx.QueryRow(`SELECT id FROM folders WHERE account_id = ? AND folder_type = 'inbox'`, accountID).Scan(&inboxID); err != nil {
		return fmt.Errorf("finding POP3 Inbox: %w", err)
	}
	if err := tx.QueryRow(`SELECT id FROM folders WHERE account_id = ? AND folder_type = 'trash'`, accountID).Scan(&trashID); err != nil {
		return fmt.Errorf("finding POP3 Trash: %w", err)
	}
	for _, id := range messageIDs {
		result, err := tx.Exec(`UPDATE messages SET folder_id = ?, is_deleted = 1
			WHERE id = ? AND account_id = ? AND folder_id = ? AND is_deleted = 0`, trashID, id, accountID, inboxID)
		if err != nil {
			return fmt.Errorf("deleting POP3 message: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return fmt.Errorf("POP3 message %d is no longer in this maildrop", id)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	_ = db.UpdateFolderCounts(inboxID)
	_ = db.UpdateFolderCounts(trashID)
	return nil
}
