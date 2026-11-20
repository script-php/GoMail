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
	for _, table := range backupTables {
		var count int64
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			return nil, fmt.Errorf("counting %s: %w", table, err)
		}
		result[table] = count
	}
	return result, nil
}

// Keep this list in step with the persisted tables in schema.sql and
// schema_mysql.sql. Archive manifests use these counts to check imports.
var backupTables = []string{
	"domains", "accounts", "domain_report_recipients", "smtp_auth_policy",
	"smtp_user_auth_policy", "smtp_app_passwords", "aliases", "folders",
	"messages", "imap_mailboxes", "imap_message_state", "imap_keywords",
	"imap_subscriptions", "imap_expunge_history", "attachments", "outbound_queue",
	"outbound_queue_events", "outbound_queue_retention", "issued_verp", "sessions",
	"backup_settings", "report_inbox_settings", "received_reports",
	"report_inbox_failures", "outbound_account_usage", "dmarc_feedback",
	"dmarc_report_log", "tls_failures", "mta_sts_policy_cache", "greylisting",
	"tarpitting", "verp_bounces",
}

// BackupTables returns the allowlisted persisted tables in an archive manifest.
func BackupTables() []string { return append([]string(nil), backupTables...) }
