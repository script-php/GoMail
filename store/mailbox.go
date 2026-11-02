package store

import (
	"database/sql"
	"fmt"
	"strings"
)

func escapedSearchPattern(query string) string {
	return "%" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(query) + "%"
}

func mysqlCaseInsensitiveSearch(where string) string {
	for _, field := range []string{"subject", "from_addr", "to_addr", "text_body"} {
		where = strings.ReplaceAll(where, field+" LIKE", field+" COLLATE utf8mb4_unicode_ci LIKE")
	}
	return where
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
	}
	for _, id := range ids {
		var direction, sourceType string
		var sourceFolderID int64
		if err := tx.QueryRow(`SELECT m.direction, f.folder_type, f.id FROM messages m JOIN folders f ON f.id=m.folder_id WHERE m.id = ? AND m.account_id = ? AND f.account_id = ?`, id, accountID, accountID).Scan(&direction, &sourceType, &sourceFolderID); err != nil {
			return sql.ErrNoRows
		}
		if action == "move" {
			if sourceFolderID == folderID {
				return fmt.Errorf("message is already in that folder")
			}
			if err := validateMessageMove(direction, sourceType, destinationType, false); err != nil {
				return err
			}
		}
		if action == "restore" && sourceType != "trash" {
			return fmt.Errorf("only trashed messages can be restored")
		}
		if action == "trash" && sourceType == "trash" {
			return fmt.Errorf("message is already in Trash")
		}
	}
	for _, id := range ids {
		switch action {
		case "read", "unread":
			_, err = tx.Exec(`UPDATE messages SET is_read = ? WHERE id = ? AND account_id = ?`, action == "read", id, accountID)
			if err == nil {
				err = db.touchIMAPMessageState(tx, id)
			}
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
				} else if direction == "draft" {
					kind = "drafts"
				}
			}
			if action != "move" {
				if err = tx.QueryRow(`SELECT id FROM folders WHERE account_id = ? AND folder_type = ?`, accountID, kind).Scan(&target); err != nil {
					return err
				}
			}
			_, err = tx.Exec(`UPDATE messages SET folder_id = ?, is_deleted = ? WHERE id = ? AND account_id = ?`, target, kind == "trash", id, accountID)
			if err == nil {
				err = db.moveIMAPMessageState(tx, id, target)
			}
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
	if err = tx.Commit(); err == nil {
		db.NotifyIMAPChanges(accountID)
	}
	return err
}

// validateMessageMove keeps system folders consistent with immutable message
// direction. fromTrash is used only by IMAP MOVE as its restore equivalent.
func validateMessageMove(direction, sourceType, destinationType string, fromTrash bool) error {
	if destinationType == "drafts" {
		return fmt.Errorf("messages cannot be moved into Drafts")
	}
	if sourceType == "trash" {
		if fromTrash && destinationType == restoreFolderForDirection(direction) {
			return nil
		}
		return fmt.Errorf("trashed messages can only be restored")
	}
	if direction == "draft" {
		return fmt.Errorf("drafts cannot be moved")
	}
	if destinationType == "trash" {
		return nil
	}
	if direction == "inbound" && (destinationType == "spam" || destinationType == "custom" || sourceType == "spam" && destinationType == "inbox") {
		return nil
	}
	return fmt.Errorf("destination folder is not allowed for this message")
}

func restoreFolderForDirection(direction string) string {
	switch direction {
	case "outbound":
		return "sent"
	case "draft":
		return "drafts"
	default:
		return "inbox"
	}
}
