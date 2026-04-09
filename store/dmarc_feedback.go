package store

import (
	"time"
)

// SaveDMARCFeedback records a DMARC authentication result for aggregate reporting
func (db *DB) SaveDMARCFeedback(domain, sourceIP, envelopeFromDomain, dkimResult, spfResult, disposition string) error {
	_, err := db.Exec(`
		INSERT INTO dmarc_feedback (domain, source_ip, envelope_from_domain, dkim_result, spf_result, disposition, received_at)
		VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
	`, domain, sourceIP, envelopeFromDomain, dkimResult, spfResult, disposition)
	return err
}

// GetDMARCFeedbackForReport retrieves aggregated DMARC feedback for a domain within a time range
// Returns: map[sourceIP]stats for building DMARC aggregate report
func (db *DB) GetDMARCFeedbackForReport(domain string, startTime, endTime time.Time) (map[string]int, error) {
	rows, err := db.Query(`
		SELECT source_ip, COUNT(*) as count
		FROM dmarc_feedback
		WHERE domain = ? AND received_at >= datetime(?) AND received_at < datetime(?)
		GROUP BY source_ip
		ORDER BY count DESC
	`, domain, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make(map[string]int)
	for rows.Next() {
		var sourceIP string
		var count int
		if err := rows.Scan(&sourceIP, &count); err != nil {
			return nil, err
		}
		results[sourceIP] = count
	}
	return results, rows.Err()
}

// CleanOldDMARCFeedback removes records older than retentionDays days
func (db *DB) CleanOldDMARCFeedback(retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	_, err := db.Exec(`
		DELETE FROM dmarc_feedback WHERE received_at < datetime(?)
	`, cutoff.Format(time.RFC3339))
	return err
}

// MarkDMARCFeedbackAsSent marks all unsent records for a domain in a time range as sent
func (db *DB) MarkDMARCFeedbackAsSent(domain string, startTime, endTime time.Time) error {
	_, err := db.Exec(`
		UPDATE dmarc_feedback
		SET sent_at = datetime('now')
		WHERE domain = ? AND received_at >= datetime(?) AND received_at < datetime(?) AND sent_at IS NULL
	`, domain, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))
	return err
}

// GetLastDMARCReportTime returns when the last report was sent for a domain (or epoch if never sent)
func (db *DB) GetLastDMARCReportTime(domain string) (time.Time, error) {
	var lastSent *time.Time
	err := db.QueryRow(`
		SELECT last_sent_at FROM dmarc_report_log WHERE domain = ?
	`, domain).Scan(&lastSent)
	
	if err != nil {
		// Domain not in log yet, return epoch time (Jan 1, 1970)
		return time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC), nil
	}
	
	if lastSent == nil {
		return time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC), nil
	}
	
	return *lastSent, nil
}

// UpdateLastDMARCReportTime records when a report was successfully sent for a domain
func (db *DB) UpdateLastDMARCReportTime(domain string) error {
	_, err := db.Exec(`
		INSERT INTO dmarc_report_log (domain, last_sent_at) 
		VALUES (?, datetime('now'))
		ON CONFLICT(domain) DO UPDATE SET last_sent_at = datetime('now')
	`, domain)
	return err
}
