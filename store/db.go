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

	return &DB{
		DB:              sqlDB,
		attachmentsPath: attachmentsPath,
	}, nil
}

// AttachmentsPath returns the base path for attachment file storage.
func (db *DB) AttachmentsPath() string {
	return db.attachmentsPath
}
