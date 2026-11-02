package store

import (
	"database/sql"
	"fmt"

	"gomail/logging"
)

// Folder represents a mailbox/folder for organizing messages.
type Folder struct {
	ID          int64
	AccountID   int64
	Name        string // Inbox, Sent, Spam, Drafts, Trash, or custom
	FolderType  string // inbox, sent, spam, drafts, trash, custom
	IsDefault   bool
	UnreadCount int
	TotalCount  int
}

// DefaultFolders creates the standard set of folders for a new account.
func (db *DB) DefaultFolders(accountID int64) error {
	return db.defaultFolders(db, accountID)
}

func (db *DB) defaultFolders(executor sqlExecutor, accountID int64) error {
	folders := []struct {
		name  string
		fType string
	}{
		{"Inbox", "inbox"},
		{"Sent", "sent"},
		{"Spam", "spam"},
		{"Drafts", "drafts"},
		{"Trash", "trash"},
	}

	for _, f := range folders {
		query := `INSERT INTO folders (account_id, name, folder_type, is_default) VALUES (?, ?, ?, 1) ON CONFLICT(account_id, name) DO NOTHING`
		if db.IsMySQL() {
			query = `INSERT INTO folders (account_id, name, folder_type, is_default) VALUES (?, ?, ?, 1) ON DUPLICATE KEY UPDATE id = id`
		}
		_, err := executor.Exec(query, accountID, f.name, f.fType)
		if err != nil {
			logging.Error(fmt.Sprintf("[store] failed to create default folder %s for account %d: %v", f.name, accountID, err))
			return fmt.Errorf("creating default folder %s: %w", f.name, err)
		}
		var folderID int64
		if err := executor.QueryRow(`SELECT id FROM folders WHERE account_id = ? AND name = ?`, accountID, f.name).Scan(&folderID); err != nil {
			return fmt.Errorf("loading default folder %s: %w", f.name, err)
		}
		if err := db.ensureIMAPMailbox(executor, folderID); err != nil {
			return fmt.Errorf("creating IMAP state for folder %s: %w", f.name, err)
		}
		subscribe := `INSERT INTO imap_subscriptions(account_id, folder_id) VALUES(?, ?) ON CONFLICT(account_id, folder_id) DO NOTHING`
		if db.IsMySQL() {
			subscribe = `INSERT INTO imap_subscriptions(account_id, folder_id) VALUES(?, ?) ON DUPLICATE KEY UPDATE folder_id = folder_id`
		}
		if _, err := executor.Exec(subscribe, accountID, folderID); err != nil {
			return fmt.Errorf("subscribing default folder %s: %w", f.name, err)
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
		logging.Error(fmt.Sprintf("[store] failed to get folder %s for account %d: %v", name, accountID, err))
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
		logging.Error(fmt.Sprintf("[store] failed to get %s folder for account %d: %v", folderType, accountID, err))
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
