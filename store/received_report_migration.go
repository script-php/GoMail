package store

import "fmt"

// Older schemas constrained one report per source message and kind. TLS-RPT
// attachments can cover multiple hosted domains, so the domain is now part of
// that uniqueness key. The dedupe_key remains globally unique.
func (db *DB) migrateReceivedReportDomainUnique() error {
	if db.driver == "mysql" {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='received_reports' AND INDEX_NAME='uq_received_report_source'`).Scan(&count); err != nil {
			return err
		}
		if count > 0 {
			if _, err := db.Exec(`ALTER TABLE received_reports DROP INDEX uq_received_report_source`); err != nil {
				return err
			}
		}
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE received_reports_domain_new (id INTEGER PRIMARY KEY AUTOINCREMENT,account_id INTEGER NOT NULL,source_message_id INTEGER NOT NULL,dedupe_key TEXT NOT NULL UNIQUE,kind TEXT NOT NULL,report_domain TEXT NOT NULL,submitter TEXT NOT NULL,report_id TEXT NOT NULL,period_start TEXT NOT NULL,period_end TEXT NOT NULL,successes INTEGER NOT NULL DEFAULT 0,failures INTEGER NOT NULL DEFAULT 0,payload_json TEXT NOT NULL,received_at DATETIME NOT NULL DEFAULT (datetime('now')),UNIQUE(account_id,source_message_id,kind,report_domain))`,
		`INSERT INTO received_reports_domain_new(id,account_id,source_message_id,dedupe_key,kind,report_domain,submitter,report_id,period_start,period_end,successes,failures,payload_json,received_at) SELECT id,account_id,source_message_id,dedupe_key,kind,report_domain,submitter,report_id,period_start,period_end,successes,failures,payload_json,received_at FROM received_reports`,
		`DROP TABLE received_reports`,
		`ALTER TABLE received_reports_domain_new RENAME TO received_reports`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("migrating received report uniqueness: %w", err)
		}
	}
	return tx.Commit()
}
