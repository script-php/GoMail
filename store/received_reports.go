package store

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type ReportInboxSettings struct {
	Enabled       bool
	AccountID     int64
	LastMessageID int64
}

func (db *DB) RetryableReportMessages(accountID int64, limit int) ([]ReportSourceMessage, error) {
	rows, err := db.Query(`SELECT m.id, CASE WHEN LENGTH(m.raw_message)<=? THEN m.raw_message ELSE NULL END FROM report_inbox_failures f JOIN messages m ON m.id=f.message_id AND m.account_id=f.account_id WHERE f.account_id=? AND f.next_retry_unix<=? ORDER BY f.next_retry_unix,m.id LIMIT ?`, 4<<20, accountID, time.Now().Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var messages []ReportSourceMessage
	for rows.Next() {
		var m ReportSourceMessage
		if err := rows.Scan(&m.ID, &m.Raw); err != nil {
			return nil, err
		}
		messages = append(messages, m)
	}
	return messages, rows.Err()
}

func (db *DB) MarkReportInboxFailure(accountID, messageID int64, cause error) error {
	reason := cause.Error()
	if len(reason) > 500 {
		reason = reason[:500]
	}
	next := time.Now().Add(time.Hour).Unix()
	_, err := db.ExecuteUpsert(
		`INSERT INTO report_inbox_failures(account_id,message_id,next_retry_unix,attempts,last_error) VALUES(?,?,?,1,?) ON CONFLICT(account_id,message_id) DO UPDATE SET next_retry_unix=excluded.next_retry_unix,attempts=attempts+1,last_error=excluded.last_error`,
		`INSERT INTO report_inbox_failures(account_id,message_id,next_retry_unix,attempts,last_error) VALUES(?,?,?,1,?) ON DUPLICATE KEY UPDATE next_retry_unix=VALUES(next_retry_unix),attempts=attempts+1,last_error=VALUES(last_error)`, accountID, messageID, next, reason)
	return err
}

func (db *DB) ClearReportInboxFailure(accountID, messageID int64) error {
	_, err := db.Exec(`DELETE FROM report_inbox_failures WHERE account_id=? AND message_id=?`, accountID, messageID)
	return err
}

func (db *DB) ResetReportInboxFailureRetries(accountID int64) error {
	_, err := db.Exec(`UPDATE report_inbox_failures SET next_retry_unix=0 WHERE account_id=?`, accountID)
	return err
}

// ResetReportInboxCursor requests a bounded, deduplicated rescan of retained
// source mail. Subsequent background ticks continue where this scan stops.
func (db *DB) ResetReportInboxCursor(accountID int64) error {
	_, err := db.Exec(`UPDATE report_inbox_settings SET last_message_id=0 WHERE id=1 AND enabled=1 AND account_id=?`, accountID)
	return err
}

type ReceivedReport struct {
	ID              int64
	AccountID       int64
	SourceMessageID int64
	Kind            string
	ReportDomain    string
	Submitter       string
	ReportID        string
	PeriodStart     string
	PeriodEnd       string
	Successes       int64
	Failures        int64
	PayloadJSON     string
	ReceivedAt      string
}

type ReportSourceMessage struct {
	ID  int64
	Raw []byte
}

type ReceivedReportTotals struct {
	DMARCCount int64
	TLSCount   int64
	Successes  int64
	Failures   int64
}

func (db *DB) GetReportInboxSettings() (ReportInboxSettings, error) {
	var settings ReportInboxSettings
	var enabled int
	err := db.QueryRow(`SELECT enabled, account_id, last_message_id FROM report_inbox_settings WHERE id=1`).Scan(&enabled, &settings.AccountID, &settings.LastMessageID)
	if err == sql.ErrNoRows {
		return settings, nil // Disabled by default.
	}
	settings.Enabled = enabled != 0
	return settings, err
}

func (db *DB) SaveReportInboxSettings(enabled bool, accountID int64) error {
	if enabled {
		if accountID <= 0 {
			return fmt.Errorf("select a local report mailbox")
		}
		account, err := db.GetAccount(accountID)
		if err != nil {
			return err
		}
		if account == nil || !account.IsActive {
			return fmt.Errorf("selected report mailbox is not active")
		}
	}
	current, err := db.GetReportInboxSettings()
	if err != nil {
		return err
	}
	cursor := current.LastMessageID
	if accountID != current.AccountID {
		cursor = 0 // Scan the new mailbox's existing reports too.
	}
	_, err = db.ExecuteUpsert(
		`INSERT INTO report_inbox_settings(id,enabled,account_id,last_message_id) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled, account_id=excluded.account_id, last_message_id=excluded.last_message_id`,
		`INSERT INTO report_inbox_settings(id,enabled,account_id,last_message_id) VALUES(1,?,?,?) ON DUPLICATE KEY UPDATE enabled=VALUES(enabled), account_id=VALUES(account_id), last_message_id=VALUES(last_message_id)`,
		boolToInt(enabled), accountID, cursor)
	return err
}

func (db *DB) ReportSourceMessages(accountID, afterID int64, limit int) ([]ReportSourceMessage, error) {
	// Do not materialize huge unrelated mail bodies in the scanner's batch.
	rows, err := db.Query(`SELECT id, CASE WHEN LENGTH(raw_message)<=? THEN raw_message ELSE NULL END FROM messages WHERE account_id=? AND direction='inbound' AND id>? ORDER BY id LIMIT ?`, 4<<20, accountID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var messages []ReportSourceMessage
	for rows.Next() {
		var message ReportSourceMessage
		if err := rows.Scan(&message.ID, &message.Raw); err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	return messages, rows.Err()
}

func (db *DB) AdvanceReportInboxCursor(accountID, messageID int64) error {
	_, err := db.Exec(`UPDATE report_inbox_settings SET last_message_id=? WHERE id=1 AND enabled=1 AND account_id=? AND last_message_id<?`, messageID, accountID, messageID)
	return err
}

func (db *DB) SaveReceivedReport(report ReceivedReport) (bool, error) {
	identity := strings.ToLower(report.Kind) + "\x00" + strings.ToLower(report.ReportDomain) + "\x00" + strings.ToLower(report.Submitter) + "\x00" + report.ReportID
	dedupeKey := fmt.Sprintf("%x", sha256.Sum256([]byte(identity)))
	result, err := db.ExecuteUpsert(
		`INSERT INTO received_reports(account_id,source_message_id,dedupe_key,kind,report_domain,submitter,report_id,period_start,period_end,successes,failures,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`,
		`INSERT INTO received_reports(account_id,source_message_id,dedupe_key,kind,report_domain,submitter,report_id,period_start,period_end,successes,failures,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE id=id`,
		report.AccountID, report.SourceMessageID, dedupeKey, report.Kind, report.ReportDomain, report.Submitter, report.ReportID, report.PeriodStart, report.PeriodEnd, report.Successes, report.Failures, report.PayloadJSON)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if affected == 0 {
		// A deliberate rescan may correct an older summary from the same
		// source message. Never let a different message with the same
		// unauthenticated report ID overwrite existing history.
		_, err = db.Exec(`UPDATE received_reports SET successes=?,failures=?,payload_json=? WHERE dedupe_key=? AND account_id=? AND source_message_id=?`, report.Successes, report.Failures, report.PayloadJSON, dedupeKey, report.AccountID, report.SourceMessageID)
		return false, err
	}
	return true, nil
}

func (db *DB) ReceivedReportSummary() (ReceivedReportTotals, error) {
	var totals ReceivedReportTotals
	err := db.QueryRow(`SELECT COALESCE(SUM(CASE WHEN kind='dmarc' THEN 1 ELSE 0 END),0), COALESCE(SUM(CASE WHEN kind='tls-rpt' THEN 1 ELSE 0 END),0), COALESCE(SUM(successes),0), COALESCE(SUM(failures),0) FROM received_reports`).Scan(&totals.DMARCCount, &totals.TLSCount, &totals.Successes, &totals.Failures)
	return totals, err
}

func (db *DB) ListReceivedReports(limit, offset int) ([]ReceivedReport, error) {
	// Keep the dashboard bounded even when a report contains many records.
	rows, err := db.Query(`SELECT id,account_id,source_message_id,kind,report_domain,submitter,report_id,period_start,period_end,successes,failures,SUBSTR(payload_json,1,4096),received_at FROM received_reports ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var reports []ReceivedReport
	for rows.Next() {
		var report ReceivedReport
		if err := rows.Scan(&report.ID, &report.AccountID, &report.SourceMessageID, &report.Kind, &report.ReportDomain, &report.Submitter, &report.ReportID, &report.PeriodStart, &report.PeriodEnd, &report.Successes, &report.Failures, &report.PayloadJSON, &report.ReceivedAt); err != nil {
			return nil, err
		}
		reports = append(reports, report)
	}
	return reports, rows.Err()
}
