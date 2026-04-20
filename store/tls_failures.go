package store

import (
	"fmt"
	"time"
)

// RecordTLSFailure records a TLS connection failure for TLS-RPT report generation
func (db *DB) RecordTLSFailure(recipientDomain, failureReason, sendingMTAIP, receivingMXHostname, receivingIP string) error {
	_, err := db.Exec(`
		INSERT INTO tls_failures (recipient_domain, failure_reason, sending_mta_ip, receiving_mx_hostname, receiving_ip, attempted_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'))
	`, recipientDomain, failureReason, sendingMTAIP, receivingMXHostname, receivingIP)
	return err
}

// TLSFailureRecord represents a single TLS failure entry
type TLSFailureRecord struct {
	RecipientDomain     string
	FailureReason       string
	SendingMTAIP        string
	ReceivingMXHostname string
	ReceivingIP         string
	AttemptedAt         time.Time
}

// GetTLSFailuresForReport retrieves aggregated TLS failures for a domain within a time range
// Returns: list of failure records and count summary
func (db *DB) GetTLSFailuresForReport(domain string, startTime, endTime time.Time) ([]TLSFailureRecord, error) {
	rows, err := db.Query(`
		SELECT recipient_domain, failure_reason, sending_mta_ip, receiving_mx_hostname, receiving_ip, attempted_at
		FROM tls_failures
		WHERE recipient_domain = ? AND attempted_at >= datetime(?) AND attempted_at < datetime(?) AND sent_at IS NULL
		ORDER BY attempted_at DESC
	`, domain, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("querying TLS failures: %w", err)
	}
	defer rows.Close()

	var failures []TLSFailureRecord
	for rows.Next() {
		var record TLSFailureRecord
		var attemptedAtStr string
		if err := rows.Scan(&record.RecipientDomain, &record.FailureReason, &record.SendingMTAIP,
			&record.ReceivingMXHostname, &record.ReceivingIP, &attemptedAtStr); err != nil {
			return nil, err
		}
		record.AttemptedAt, _ = time.Parse(time.RFC3339, attemptedAtStr)
		failures = append(failures, record)
	}
	return failures, rows.Err()
}

// GetDomainsWithTLSFailures returns list of domains that have unreported TLS failures
func (db *DB) GetDomainsWithTLSFailures() ([]string, error) {
	rows, err := db.Query(`
		SELECT DISTINCT recipient_domain
		FROM tls_failures
		WHERE sent_at IS NULL
		ORDER BY recipient_domain
	`)
	if err != nil {
		return nil, fmt.Errorf("querying domains with TLS failures: %w", err)
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	return domains, rows.Err()
}

// CountTLSFailuresByReason returns count of failures grouped by reason for a domain and time range
func (db *DB) CountTLSFailuresByReason(domain string, startTime, endTime time.Time) (map[string]int, error) {
	rows, err := db.Query(`
		SELECT failure_reason, COUNT(*) as count
		FROM tls_failures
		WHERE recipient_domain = ? AND attempted_at >= datetime(?) AND attempted_at < datetime(?) AND sent_at IS NULL
		GROUP BY failure_reason
		ORDER BY count DESC
	`, domain, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make(map[string]int)
	for rows.Next() {
		var reason string
		var count int
		if err := rows.Scan(&reason, &count); err != nil {
			return nil, err
		}
		results[reason] = count
	}
	return results, rows.Err()
}

// MarkTLSFailuresAsReported marks all unsent records for a domain in a time range as sent
func (db *DB) MarkTLSFailuresAsReported(domain string, startTime, endTime time.Time) error {
	_, err := db.Exec(`
		UPDATE tls_failures
		SET sent_at = datetime('now')
		WHERE recipient_domain = ? AND attempted_at >= datetime(?) AND attempted_at < datetime(?) AND sent_at IS NULL
	`, domain, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))
	return err
}

// CleanOldTLSFailures removes records older than retentionDays days
func (db *DB) CleanOldTLSFailures(retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	_, err := db.Exec(`
		DELETE FROM tls_failures WHERE attempted_at < datetime(?)
	`, cutoff.Format(time.RFC3339))
	return err
}
