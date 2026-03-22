package store

import (
	"database/sql"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// DB wraps the SQLite database connection.
type DB struct {
	*sql.DB
	attachmentsPath string
}

// Open opens (or creates) the SQLite database and runs migrations.
func Open(dbPath, attachmentsPath string) (*DB, error) {
	// Ensure directories exist
	if err := os.MkdirAll(filepath.Dir(dbPath), 0750); err != nil {
		return nil, fmt.Errorf("creating db directory: %w", err)
	}
	if err := os.MkdirAll(attachmentsPath, 0750); err != nil {
		return nil, fmt.Errorf("creating attachments directory: %w", err)
	}

	// Open SQLite with WAL mode for concurrent reads
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=ON", dbPath)
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Set connection pool (SQLite doesn't benefit from many connections)
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	// Run schema
	if _, err := sqlDB.Exec(schemaSQL); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("running schema migration: %w", err)
	}

	db := &DB{
		DB:              sqlDB,
		attachmentsPath: attachmentsPath,
	}

	// Migrate existing accounts to have folders if they don't already
	if err := db.migrateExistingAccounts(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("migrating existing accounts: %w", err)
	}

	return db, nil
}

// AttachmentsPath returns the base path for attachment file storage.
func (db *DB) AttachmentsPath() string {
	return db.attachmentsPath
}

// migrateExistingAccounts creates default folders for any accounts that don't have them yet,
// and assigns existing messages to their appropriate folders based on direction.
// This handles accounts created before the folder system was added.
func (db *DB) migrateExistingAccounts() error {
	// Get all account IDs
	rows, err := db.Query("SELECT id FROM accounts")
	if err != nil {
		return err
	}
	defer rows.Close()

	var accountIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		accountIDs = append(accountIDs, id)
	}
	if err = rows.Err(); err != nil {
		return err
	}

	// For each account, check if it has folders and create them if missing
	for _, accountID := range accountIDs {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM folders WHERE account_id = ?", accountID).Scan(&count)
		if err != nil {
			return err
		}

		// If account has no folders, create the defaults
		if count == 0 {
			if err := db.DefaultFolders(accountID); err != nil {
				// Log but don't fail - continue with other accounts
				fmt.Printf("warning: failed to create folders for account %d: %v\n", accountID, err)
				continue
			}
		}

		// Assign existing messages to folders based on direction
		// Inbound messages -> Inbox folder
		inboxFolder, err := db.GetFolderByType(accountID, "inbox")
		if err == nil && inboxFolder != nil {
			_, err = db.Exec(`
				UPDATE messages SET folder_id = ? 
				WHERE account_id = ? AND direction = 'inbound' AND folder_id IS NULL
			`, inboxFolder.ID, accountID)
			if err != nil {
				fmt.Printf("warning: failed to assign inbound messages for account %d: %v\n", accountID, err)
			}
		}

		// Outbound messages -> Sent folder
		sentFolder, err := db.GetFolderByType(accountID, "sent")
		if err == nil && sentFolder != nil {
			_, err = db.Exec(`
				UPDATE messages SET folder_id = ? 
				WHERE account_id = ? AND direction = 'outbound' AND folder_id IS NULL
			`, sentFolder.ID, accountID)
			if err != nil {
				fmt.Printf("warning: failed to assign outbound messages for account %d: %v\n", accountID, err)
			}
		}
	}

	return nil
}

