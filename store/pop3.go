package store

import "fmt"

// POP3Message is the immutable snapshot exposed during one POP3 maildrop session.
type POP3Message struct {
	ID     int64
	Octets int
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
		var raw []byte
		if err := rows.Scan(&message.ID, &raw); err != nil {
			return nil, fmt.Errorf("scanning POP3 maildrop: %w", err)
		}
		message.Octets = pop3CanonicalOctets(raw)
		messages = append(messages, message)
	}
	return messages, rows.Err()
}

// GetPOP3MessageRaw loads one message body when RETR or TOP needs it.
func (db *DB) GetPOP3MessageRaw(accountID, messageID int64) ([]byte, error) {
	var raw []byte
	err := db.QueryRow(`SELECT m.raw_message FROM messages m
		JOIN folders f ON f.id=m.folder_id
		WHERE m.id=? AND m.account_id=? AND f.account_id=?
		AND f.folder_type='inbox' AND m.direction='inbound' AND m.is_deleted=0`,
		messageID, accountID, accountID).Scan(&raw)
	return raw, err
}

func pop3CanonicalOctets(raw []byte) int {
	if len(raw) == 0 {
		return 0
	}
	n := 0
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '\r':
			n += 2
			if i+1 < len(raw) && raw[i+1] == '\n' {
				i++
			}
		case '\n':
			n += 2
		default:
			n++
		}
	}
	if last := raw[len(raw)-1]; last != '\r' && last != '\n' {
		n += 2
	}
	return n
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
		if err := db.moveIMAPMessageState(tx, id, trashID); err != nil {
			return fmt.Errorf("updating IMAP state for POP3 message %d: %w", id, err)
		}
	}
	if err := updateAccountFolderCounts(tx, accountID); err != nil {
		return fmt.Errorf("updating POP3 folder counts: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	db.NotifyIMAPChanges(accountID)
	return nil
}
