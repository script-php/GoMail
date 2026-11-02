package store

import (
	"fmt"
	"time"
)

type MessageCursor struct {
	ReceivedAt time.Time
	ID         int64
	Direction  string // older or newer
}

type MessagePage struct {
	Messages []*Message
	HasOlder bool
	HasNewer bool
}

func (db *DB) ListMessagesPage(accountID int64, direction string, limit int, cursor *MessageCursor) (MessagePage, error) {
	where := `account_id = ? AND direction = ? AND is_deleted = 0`
	args := []interface{}{accountID, direction}
	return db.queryMessagePage(where, args, limit, cursor)
}

func (db *DB) ListFolderMessagesPage(accountID, folderID int64, limit int, cursor *MessageCursor) (MessagePage, error) {
	where := `account_id = ? AND folder_id = ?`
	args := []interface{}{accountID, folderID}
	return db.queryMessagePage(where, args, limit, cursor)
}

// ListStarredMessagesPage lists non-trashed starred messages across folders.
func (db *DB) ListStarredMessagesPage(accountID int64, limit int, cursor *MessageCursor) (MessagePage, error) {
	return db.queryMessagePage(`account_id = ? AND is_starred = 1 AND is_deleted = 0`, []interface{}{accountID}, limit, cursor)
}

func (db *DB) CountStarredMessages(accountID int64) (int, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE account_id = ? AND is_starred = 1 AND is_deleted = 0`, accountID).Scan(&count)
	return count, err
}

func (db *DB) SearchMessagesPage(accountID int64, query string, limit int, cursor *MessageCursor) (MessagePage, int, error) {
	pattern := escapedSearchPattern(query)
	where := `account_id = ? AND is_deleted = 0 AND (subject LIKE ? ESCAPE '!' OR from_addr LIKE ? ESCAPE '!' OR to_addr LIKE ? ESCAPE '!' OR text_body LIKE ? ESCAPE '!')`
	if db.IsMySQL() {
		where = mysqlCaseInsensitiveSearch(where)
	}
	args := []interface{}{accountID, pattern, pattern, pattern, pattern}
	var total int
	if err := db.QueryRow("SELECT COUNT(*) FROM messages WHERE "+where, args...).Scan(&total); err != nil {
		return MessagePage{}, 0, err
	}
	page, err := db.queryMessagePage(where, args, limit, cursor)
	return page, total, err
}

func (db *DB) queryMessagePage(where string, args []interface{}, limit int, cursor *MessageCursor) (MessagePage, error) {
	if limit < 1 || limit > 200 {
		return MessagePage{}, fmt.Errorf("invalid page size")
	}
	order := "received_at DESC, id DESC"
	if cursor != nil {
		operator := "<"
		if cursor.Direction == "newer" {
			operator = ">"
			order = "received_at ASC, id ASC"
		} else if cursor.Direction != "older" {
			return MessagePage{}, fmt.Errorf("invalid cursor direction")
		}
		where += fmt.Sprintf(" AND (received_at %s ? OR (received_at = ? AND id %s ?))", operator, operator)
		boundary := databaseTime(cursor.ReceivedAt)
		args = append(args, boundary, boundary, cursor.ID)
	}
	args = append(args, limit+1)
	rows, err := db.Query(`SELECT id, account_id, folder_id, message_id, direction, mail_from, rcpt_to,
		from_addr, to_addr, subject, size, has_attachments, is_read, is_starred,
		spf_result, dkim_result, dmarc_result, received_at
		FROM messages WHERE `+where+` ORDER BY `+order+` LIMIT ?`, args...)
	if err != nil {
		return MessagePage{}, err
	}
	defer rows.Close()
	var messages []*Message
	for rows.Next() {
		message := &Message{}
		var hasAttachments, isRead, isStarred int
		if err := rows.Scan(&message.ID, &message.AccountID, &message.FolderID, &message.MessageID, &message.Direction,
			&message.MailFrom, &message.RcptTo, &message.FromAddr, &message.ToAddr, &message.Subject, &message.Size,
			&hasAttachments, &isRead, &isStarred, &message.SPFResult, &message.DKIMResult, &message.DMARCResult, &message.ReceivedAt); err != nil {
			return MessagePage{}, err
		}
		message.HasAttachments = hasAttachments != 0
		message.IsRead = isRead != 0
		message.IsStarred = isStarred != 0
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		return MessagePage{}, err
	}
	hasExtra := len(messages) > limit
	if hasExtra {
		messages = messages[:limit]
	}
	page := MessagePage{Messages: messages}
	if cursor == nil {
		page.HasOlder = hasExtra
	} else if cursor.Direction == "older" {
		page.HasNewer = true
		page.HasOlder = hasExtra
	} else {
		page.HasOlder = true
		page.HasNewer = hasExtra
		reverseMessages(messages)
	}
	return page, nil
}

func reverseMessages(messages []*Message) {
	for left, right := 0, len(messages)-1; left < right; left, right = left+1, right-1 {
		messages[left], messages[right] = messages[right], messages[left]
	}
}
