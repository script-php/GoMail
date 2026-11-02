package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"gomail/logging"
)

// TLSEvent records one policy evaluation for TLS-RPT aggregation.
type TLSEvent struct {
	RecipientDomain       string
	Successful            bool
	FailureReason         string
	SendingMTAIP          string
	ReceivingMXHostname   string
	ReceivingIP           string
	PolicyType            string
	PolicyString          []string
	PolicyDomain          string
	MXHostPattern         []string
	AdditionalInformation string
	FailureReasonCode     string
}

// RecordTLSEvent stores a successful or failed policy evaluation.
func (db *DB) RecordTLSEvent(event TLSEvent) error {
	policyString, err := json.Marshal(event.PolicyString)
	if err != nil {
		return fmt.Errorf("encoding TLS policy: %w", err)
	}
	mxPattern, err := json.Marshal(event.MXHostPattern)
	if err != nil {
		return fmt.Errorf("encoding TLS MX pattern: %w", err)
	}
	if event.PolicyType == "" {
		event.PolicyType = "no-policy-found"
	}
	if event.PolicyDomain == "" {
		event.PolicyDomain = event.RecipientDomain
	}
	_, err = db.Exec(`
		INSERT INTO tls_failures
		(recipient_domain, failure_reason, sending_mta_ip, receiving_mx_hostname,
		 receiving_ip, successful, policy_type, policy_string, policy_domain,
		 mx_host_pattern, additional_information, failure_reason_code, attempted_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`, event.RecipientDomain, event.FailureReason, event.SendingMTAIP,
		event.ReceivingMXHostname, event.ReceivingIP, event.Successful,
		event.PolicyType, string(policyString), event.PolicyDomain, string(mxPattern),
		event.AdditionalInformation, event.FailureReasonCode)
	if err != nil {
		logging.Error(fmt.Sprintf("[store] failed to record TLS event for %s: %v", event.RecipientDomain, err))
	}
	return err
}

// RecordTLSFailure records a TLS connection failure for TLS-RPT report generation
func (db *DB) RecordTLSFailure(recipientDomain, failureReason, sendingMTAIP, receivingMXHostname, receivingIP string) error {
	return db.RecordTLSEvent(TLSEvent{RecipientDomain: recipientDomain, FailureReason: failureReason,
		SendingMTAIP: sendingMTAIP, ReceivingMXHostname: receivingMXHostname,
		ReceivingIP: receivingIP, PolicyType: "no-policy-found", PolicyDomain: recipientDomain})
}

// TLSFailureRecord represents a single TLS failure entry
type TLSFailureRecord struct {
	RecipientDomain       string
	FailureReason         string
	SendingMTAIP          string
	ReceivingMXHostname   string
	ReceivingIP           string
	AttemptedAt           time.Time
	Successful            bool
	PolicyType            string
	PolicyString          []string
	PolicyDomain          string
	MXHostPattern         []string
	AdditionalInformation string
	FailureReasonCode     string
}

// GetTLSFailuresForReport retrieves aggregated TLS failures for a domain within a time range
// Returns: list of failure records and count summary
func (db *DB) GetTLSFailuresForReport(domain string, startTime, endTime time.Time) ([]TLSFailureRecord, error) {
	rows, err := db.Query(`
		SELECT recipient_domain, failure_reason, sending_mta_ip, receiving_mx_hostname,
		       receiving_ip, attempted_at, successful, policy_type, policy_string,
		       policy_domain, mx_host_pattern, additional_information, failure_reason_code
		FROM tls_failures
		WHERE recipient_domain = ? AND attempted_at >= ? AND attempted_at < ? AND sent_at IS NULL
		ORDER BY attempted_at DESC
	`, domain, databaseTime(startTime), databaseTime(endTime))
	if err != nil {
		logging.Error(fmt.Sprintf("[store] failed to query TLS failures for %s: %v", domain, err))
		return nil, fmt.Errorf("querying TLS failures: %w", err)
	}
	defer rows.Close()

	var failures []TLSFailureRecord
	for rows.Next() {
		var record TLSFailureRecord
		var policyString, mxPattern string
		var additionalInformation, failureReasonCode sql.NullString
		if err := rows.Scan(&record.RecipientDomain, &record.FailureReason, &record.SendingMTAIP,
			&record.ReceivingMXHostname, &record.ReceivingIP, &record.AttemptedAt,
			&record.Successful, &record.PolicyType, &policyString, &record.PolicyDomain,
			&mxPattern, &additionalInformation, &failureReasonCode); err != nil {
			return nil, err
		}
		record.AdditionalInformation = additionalInformation.String
		record.FailureReasonCode = failureReasonCode.String
		if err := json.Unmarshal([]byte(policyString), &record.PolicyString); err != nil {
			return nil, fmt.Errorf("decoding TLS policy string: %w", err)
		}
		if err := json.Unmarshal([]byte(mxPattern), &record.MXHostPattern); err != nil {
			return nil, fmt.Errorf("decoding TLS MX pattern: %w", err)
		}
		if record.PolicyDomain == "" {
			record.PolicyDomain = record.RecipientDomain
		}
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
		WHERE recipient_domain = ? AND attempted_at >= ? AND attempted_at < ? AND sent_at IS NULL
		GROUP BY failure_reason
		ORDER BY count DESC
	`, domain, databaseTime(startTime), databaseTime(endTime))
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
		SET sent_at = CURRENT_TIMESTAMP
		WHERE recipient_domain = ? AND attempted_at >= ? AND attempted_at < ? AND sent_at IS NULL
	`, domain, databaseTime(startTime), databaseTime(endTime))
	return err
}

// GetTLSReportStart returns the earliest eligible unreported event. Failed
// deliveries retain this boundary so the same reporting window is retried.
func (db *DB) GetTLSReportStart(domain string, endTime time.Time) (time.Time, bool, error) {
	var raw sql.NullString
	err := db.QueryRow(`
		SELECT MIN(attempted_at) FROM tls_failures
		WHERE recipient_domain = ? AND attempted_at < ? AND sent_at IS NULL
		  AND (next_report_attempt IS NULL OR next_report_attempt <= ?)
	`, domain, databaseTime(endTime), databaseTime(time.Now())).Scan(&raw)
	if err != nil || !raw.Valid {
		return time.Time{}, false, err
	}
	for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339, "2006-01-02T15:04:05Z07:00"} {
		if parsed, parseErr := time.Parse(layout, raw.String); parseErr == nil {
			return parsed.UTC(), true, nil
		}
	}
	return time.Time{}, false, fmt.Errorf("parsing TLS report window start %q", raw.String)
}

// RecordTLSReportFailure stores explicit bounded-backoff retry state.
func (db *DB) RecordTLSReportFailure(domain string, startTime, endTime time.Time, deliveryErr error) error {
	var attempts int
	if err := db.QueryRow(`SELECT COALESCE(MAX(report_attempts), 0) FROM tls_failures
		WHERE recipient_domain = ? AND attempted_at >= ? AND attempted_at < ? AND sent_at IS NULL`,
		domain, databaseTime(startTime), databaseTime(endTime)).Scan(&attempts); err != nil {
		return err
	}
	delay := time.Hour << min(attempts, 4)
	next := time.Now().UTC().Add(delay)
	_, err := db.Exec(`UPDATE tls_failures
		SET report_attempts = report_attempts + 1, next_report_attempt = ?, report_last_error = ?
		WHERE recipient_domain = ? AND attempted_at >= ? AND attempted_at < ? AND sent_at IS NULL`,
		databaseTime(next), deliveryErr.Error(), domain, databaseTime(startTime), databaseTime(endTime))
	return err
}

// CleanOldTLSFailures removes records older than retentionDays days
func (db *DB) CleanOldTLSFailures(retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	_, err := db.Exec(`
		DELETE FROM tls_failures WHERE attempted_at < ?
	`, databaseTime(cutoff))
	return err
}
