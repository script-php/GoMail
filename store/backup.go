package store

import (
	"fmt"
	"strings"
)

func (db *DB) DriverName() string { return db.driver }

// SnapshotSQLite creates a transactionally consistent standalone SQLite file.
func (db *DB) SnapshotSQLite(destination string) error {
	if db.driver != "sqlite" {
		return fmt.Errorf("SQLite snapshot requested for %s database", db.driver)
	}
	escaped := strings.ReplaceAll(destination, "'", "''")
	if _, err := db.Exec("VACUUM INTO '" + escaped + "'"); err != nil {
		return fmt.Errorf("creating SQLite snapshot: %w", err)
	}
	return nil
}

func (db *DB) BackupCounts() (map[string]int64, error) {
	result := map[string]int64{}
	for _, table := range []string{"domains", "accounts", "messages", "attachments", "outbound_queue", "outbound_queue_events"} {
		var count int64
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			return nil, fmt.Errorf("counting %s: %w", table, err)
		}
		result[table] = count
	}
	return result, nil
}
