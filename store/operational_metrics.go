package store

import "time"

// OperationalMetrics is an aggregate-only view used by monitoring. It never
// includes addresses, domains, message identifiers, or other high-cardinality
// user data.
type OperationalMetrics struct {
	QueueByStatus      map[string]int64
	OldestPendingAge   float64
	MailboxUsedBytes   int64
	MailboxQuotaBytes  int64
	QuotaLimited       int64
	QuotaNearLimit     int64
	TLSAttempts24Hours int64
	TLSFailures24Hours int64
}

func (db *DB) GetOperationalMetrics(now time.Time) (OperationalMetrics, error) {
	result := OperationalMetrics{QueueByStatus: map[string]int64{}}
	rows, err := db.Query(`SELECT status, COUNT(*) FROM outbound_queue GROUP BY status`)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			rows.Close()
			return result, err
		}
		result.QueueByStatus[status] = count
	}
	if err := rows.Close(); err != nil {
		return result, err
	}

	var oldest *time.Time
	if err := db.QueryRow(`SELECT MIN(created_at) FROM outbound_queue WHERE status IN ('pending', 'sending')`).Scan(&oldest); err != nil {
		return result, err
	}
	if oldest != nil && now.After(*oldest) {
		result.OldestPendingAge = now.Sub(*oldest).Seconds()
	}

	if err := db.QueryRow(`SELECT COALESCE(SUM(mailbox_used_bytes), 0),
		COALESCE(SUM(quota_bytes), 0),
		COALESCE(SUM(CASE WHEN quota_bytes > 0 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN quota_bytes > 0 AND mailbox_used_bytes * 10 >= quota_bytes * 9 THEN 1 ELSE 0 END), 0)
		FROM accounts WHERE is_active = 1`).Scan(&result.MailboxUsedBytes, &result.MailboxQuotaBytes, &result.QuotaLimited, &result.QuotaNearLimit); err != nil {
		return result, err
	}

	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN successful = 0 THEN 1 ELSE 0 END), 0)
		FROM tls_failures WHERE attempted_at >= ?`, databaseTime(now.Add(-24*time.Hour))).Scan(&result.TLSAttempts24Hours, &result.TLSFailures24Hours); err != nil {
		return result, err
	}
	return result, nil
}
