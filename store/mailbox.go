package store

import (
	"database/sql"
	"fmt"
	"strings"
)

// SearchMessages searches visible mail, scoped to its owner. SQL wildcards are literal.
func (db *DB) SearchMessages(accountID int64, query string, limit, offset int) ([]*Message, int, error) {
	pattern := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(query) + "%"
	where := `account_id = ? AND is_deleted = 0 AND (subject LIKE ? ESCAPE '\' OR from_addr LIKE ? ESCAPE '\' OR to_addr LIKE ? ESCAPE '\' OR text_body LIKE ? ESCAPE '\')`
	args := []interface{}{accountID, pattern, pattern, pattern, pattern}
	var total int
	if err := db.QueryRow("SELECT COUNT(*) FROM messages WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.Query(`SELECT id, from_addr, to_addr, subject, has_attachments, is_read, is_starred, spf_result, dkim_result, dmarc_result, received_at FROM messages WHERE `+where+` ORDER BY received_at DESC, id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var messages []*Message
	for rows.Next() {
		m := &Message{}
		if err := rows.Scan(&m.ID, &m.FromAddr, &m.ToAddr, &m.Subject, &m.HasAttachments, &m.IsRead, &m.IsStarred, &m.SPFResult, &m.DKIMResult, &m.DMARCResult, &m.ReceivedAt); err != nil {
			return nil, 0, err
		}
		messages = append(messages, m)
	}
	return messages, total, rows.Err()
}

// ApplyMessageAction validates the entire selection before changing anything.
func (db *DB) ApplyMessageAction(accountID int64, ids []int64, action string, folderID int64) error {
	if len(ids) == 0 || len(ids) > 100 {
		return fmt.Errorf("select between 1 and 100 messages")
	}
	switch action {
	case "read", "unread", "trash", "restore", "move":
	default:
		return fmt.Errorf("invalid action")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var destinationType string
	if action == "move" {
		if err := tx.QueryRow(`SELECT folder_type FROM folders WHERE id = ? AND account_id = ?`, folderID, accountID).Scan(&destinationType); err != nil {
			return fmt.Errorf("destination folder not found")
		}
		if destinationType == "drafts" {
			return fmt.Errorf("received or sent messages cannot become drafts")
		}
	}
	for _, id := range ids {
		var direction string
		if err := tx.QueryRow(`SELECT direction FROM messages WHERE id = ? AND account_id = ?`, id, accountID).Scan(&direction); err != nil {
			return sql.ErrNoRows
		}
	}
	for _, id := range ids {
		switch action {
		case "read", "unread":
			_, err = tx.Exec(`UPDATE messages SET is_read = ? WHERE id = ? AND account_id = ?`, action == "read", id, accountID)
		default:
			target, kind := folderID, destinationType
			if action == "trash" {
				kind = "trash"
			}
			if action == "restore" {
				var direction string
				if err = tx.QueryRow(`SELECT direction FROM messages WHERE id = ? AND account_id = ?`, id, accountID).Scan(&direction); err != nil {
					return err
				}
				kind = "inbox"
				if direction == "outbound" {
					kind = "sent"
				}
			}
			if action != "move" {
				if err = tx.QueryRow(`SELECT id FROM folders WHERE account_id = ? AND folder_type = ?`, accountID, kind).Scan(&target); err != nil {
					return err
				}
			}
			_, err = tx.Exec(`UPDATE messages SET folder_id = ?, is_deleted = ? WHERE id = ? AND account_id = ?`, target, kind == "trash", id, accountID)
		}
		if err != nil {
			return err
		}
	}
	_, err = tx.Exec(`UPDATE folders SET
 total_count = (SELECT COUNT(*) FROM messages WHERE folder_id = folders.id AND is_deleted = (folders.folder_type = 'trash')),
 unread_count = (SELECT COUNT(*) FROM messages WHERE folder_id = folders.id AND is_read = 0 AND is_deleted = (folders.folder_type = 'trash'))
 WHERE account_id = ?`, accountID)
	if err != nil {
		return err
	}
	return tx.Commit()
}
