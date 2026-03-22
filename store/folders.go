package store

import (
	"database/sql"
	"fmt"
)

// Folder represents a mailbox/folder for organizing messages.
type Folder struct {
	ID         int64
	AccountID  int64
	Name       string // Inbox, Sent, Spam, Drafts, Trash, or custom
	FolderType string // inbox, sent, spam, drafts, trash, custom
	IsDefault  bool
	UnreadCount int
	TotalCount  int
}

// DefaultFolders creates the standard set of folders for a new account.
func (db *DB) DefaultFolders(accountID int64) error {
	folders := []struct {
		name   string
		fType  string
	}{
		{"Inbox", "inbox"},
		{"Sent", "sent"},
		{"Spam", "spam"},
		{"Drafts", "drafts"},
		{"Trash", "trash"},
	}

	for _, f := range folders {
		_, err := db.Exec(`
			INSERT OR IGNORE INTO folders (account_id, name, folder_type, is_default)
			VALUES (?, ?, ?, 1)
		`, accountID, f.name, f.fType)
		if err != nil {
			return fmt.Errorf("creating default folder %s: %w", f.name, err)
		}
	}
	return nil
}

// GetFolderByName returns a folder by account and name.
func (db *DB) GetFolderByName(accountID int64, name string) (*Folder, error) {
	var f Folder
	err := db.QueryRow(`
		SELECT id, account_id, name, folder_type, is_default, unread_count, total_count
		FROM folders WHERE account_id = ? AND name = ?
	`, accountID, name).Scan(
		&f.ID, &f.AccountID, &f.Name, &f.FolderType, &f.IsDefault,
		&f.UnreadCount, &f.TotalCount,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting folder: %w", err)
	}
	return &f, nil
}

// GetFolderByType returns a default folder by type (inbox, sent, spam, etc).
func (db *DB) GetFolderByType(accountID int64, folderType string) (*Folder, error) {
	var f Folder
	err := db.QueryRow(`
		SELECT id, account_id, name, folder_type, is_default, unread_count, total_count
		FROM folders WHERE account_id = ? AND folder_type = ?
	`, accountID, folderType).Scan(
		&f.ID, &f.AccountID, &f.Name, &f.FolderType, &f.IsDefault,
		&f.UnreadCount, &f.TotalCount,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting folder: %w", err)
	}
	return &f, nil
}

// GetFolderByID returns a folder by ID.
func (db *DB) GetFolderByID(folderID int64) (*Folder, error) {
	var f Folder
	err := db.QueryRow(`
		SELECT id, account_id, name, folder_type, is_default, unread_count, total_count
		FROM folders WHERE id = ?
	`, folderID).Scan(
		&f.ID, &f.AccountID, &f.Name, &f.FolderType, &f.IsDefault,
		&f.UnreadCount, &f.TotalCount,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting folder: %w", err)
	}
	return &f, nil
}

// ListFolders returns all folders for an account.
func (db *DB) ListFolders(accountID int64) ([]*Folder, error) {
	rows, err := db.Query(`
		SELECT id, account_id, name, folder_type, is_default, unread_count, total_count
		FROM folders WHERE account_id = ?
		ORDER BY is_default DESC, name ASC
	`, accountID)
	if err != nil {
		return nil, fmt.Errorf("listing folders: %w", err)
	}
	defer rows.Close()

	var folders []*Folder
	for rows.Next() {
		var f Folder
		if err := rows.Scan(
			&f.ID, &f.AccountID, &f.Name, &f.FolderType, &f.IsDefault,
			&f.UnreadCount, &f.TotalCount,
		); err != nil {
			return nil, fmt.Errorf("scanning folder: %w", err)
		}
		folders = append(folders, &f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("folder query error: %w", err)
	}
	return folders, nil
}

// UpdateFolderCounts updates unread and total counts for a folder.
func (db *DB) UpdateFolderCounts(folderID int64) error {
	// Get folder type to determine what to count
	var folderType string
	err := db.QueryRow(`SELECT folder_type FROM folders WHERE id = ?`, folderID).Scan(&folderType)
	if err != nil {
		return fmt.Errorf("getting folder type: %w", err)
	}

	if folderType == "trash" {
		// For trash, count deleted messages
		_, err := db.Exec(`
			UPDATE folders SET
				unread_count = (SELECT COUNT(*) FROM messages WHERE folder_id = ? AND is_read = 0 AND is_deleted = 1),
				total_count = (SELECT COUNT(*) FROM messages WHERE folder_id = ? AND is_deleted = 1)
			WHERE id = ?
		`, folderID, folderID, folderID)
		if err != nil {
			return fmt.Errorf("updating trash folder counts: %w", err)
		}
	} else {
		// For other folders, count non-deleted messages
		_, err := db.Exec(`
			UPDATE folders SET
				unread_count = (SELECT COUNT(*) FROM messages WHERE folder_id = ? AND is_read = 0 AND is_deleted = 0),
				total_count = (SELECT COUNT(*) FROM messages WHERE folder_id = ? AND is_deleted = 0)
			WHERE id = ?
		`, folderID, folderID, folderID)
		if err != nil {
			return fmt.Errorf("updating folder counts: %w", err)
		}
	}
	return nil
}

// ListMessagesInFolder returns messages in a specific folder.
func (db *DB) ListMessagesInFolder(folderID int64, limit, offset int) ([]*Message, error) {
	rows, err := db.Query(`
		SELECT id, account_id, folder_id, message_id, direction, mail_from, rcpt_to,
		       from_addr, to_addr, cc_addr, reply_to, subject, text_body, html_body,
		       raw_headers, size, has_attachments, is_read, is_starred, is_deleted,
		       spf_result, dkim_result, dmarc_result, auth_results, received_at, created_at
		FROM messages
		WHERE folder_id = ?
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`, folderID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("listing folder messages: %w", err)
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(
			&m.ID, &m.AccountID, &m.FolderID, &m.MessageID, &m.Direction, &m.MailFrom, &m.RcptTo,
			&m.FromAddr, &m.ToAddr, &m.CcAddr, &m.ReplyTo, &m.Subject, &m.TextBody, &m.HTMLBody,
			&m.RawHeaders, &m.Size, &m.HasAttachments, &m.IsRead, &m.IsStarred, &m.IsDeleted,
			&m.SPFResult, &m.DKIMResult, &m.DMARCResult, &m.AuthResults, &m.ReceivedAt, &m.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning message: %w", err)
		}
		messages = append(messages, &m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("folder message query error: %w", err)
	}
	return messages, nil
}
