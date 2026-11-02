package store

import (
	"database/sql"
	"fmt"
	"time"
)

// Zero disables automatic deletion. Pending, sending and uncertain entries
// are excluded even when their timestamps are old.
func (db *DB) QueueRetentionDays() (int, error) {
	var days int
	err := db.QueryRow(`SELECT days FROM outbound_queue_retention WHERE id = 1`).Scan(&days)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return days, err
}

func (db *DB) SetQueueRetentionDays(days int) error {
	if days < 0 || days > 3650 {
		return fmt.Errorf("queue retention must be 0–3650 days")
	}
	_, err := db.ExecuteUpsert(
		`INSERT INTO outbound_queue_retention (id, days) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET days = excluded.days`,
		`INSERT INTO outbound_queue_retention (id, days) VALUES (1, ?) ON DUPLICATE KEY UPDATE days = VALUES(days)`, days)
	return err
}

// Zero keeps archived VERP mappings indefinitely, preserving late-bounce
// attribution. This setting is independent of completed queue retention.
func (db *DB) VERPRetentionDays() (int, error) {
	var days int
	err := db.QueryRow(`SELECT verp_days FROM outbound_queue_retention WHERE id = 1`).Scan(&days)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return days, err
}

func (db *DB) SetVERPRetentionDays(days int) error {
	if days < 0 || days > 3650 {
		return fmt.Errorf("VERP retention must be 0–3650 days")
	}
	_, err := db.ExecuteUpsert(
		`INSERT INTO outbound_queue_retention (id, verp_days) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET verp_days = excluded.verp_days`,
		`INSERT INTO outbound_queue_retention (id, verp_days) VALUES (1, ?) ON DUPLICATE KEY UPDATE verp_days = VALUES(verp_days)`, days)
	return err
}

// PruneIssuedVERP removes at most limit old archived mappings. A mapping is
// kept while an active queue entry still references it, even if archived_at
// is old. After removal, a later bounce to that address is no longer accepted.
func (db *DB) PruneIssuedVERP(days int, now time.Time, limit int) (int, error) {
	if days <= 0 || days > 3650 || limit <= 0 || limit > 500 {
		return 0, fmt.Errorf("invalid VERP retention batch")
	}
	cutoff := databaseTime(now.Add(-time.Duration(days) * 24 * time.Hour))
	result, err := db.Exec(`DELETE FROM issued_verp WHERE archived_at < ?
		AND NOT EXISTS (SELECT 1 FROM outbound_queue q WHERE q.verp_bounce_address = issued_verp.address AND q.status <> 'cancelled')
		AND address IN (SELECT address FROM (SELECT candidate.address FROM issued_verp candidate
			WHERE candidate.archived_at < ? AND NOT EXISTS (SELECT 1 FROM outbound_queue q WHERE q.verp_bounce_address = candidate.address AND q.status <> 'cancelled')
			ORDER BY candidate.archived_at, candidate.address LIMIT ?) limited)`, cutoff, cutoff, limit)
	if err != nil {
		return 0, err
	}
	removed, err := result.RowsAffected()
	return int(removed), err
}

// PruneCompletedQueueEntries deletes at most limit old terminal queue rows.
// Their history cascades with them. Each delete rechecks state and age to avoid
// racing an operator retry.
func (db *DB) PruneCompletedQueueEntries(days int, now time.Time, limit int) (int, error) {
	if days <= 0 || days > 3650 || limit <= 0 || limit > 500 {
		return 0, fmt.Errorf("invalid queue retention batch")
	}
	cutoff := databaseTime(now.Add(-time.Duration(days) * 24 * time.Hour))
	rows, err := db.Query(`SELECT id FROM outbound_queue WHERE status IN ('sent', 'failed', 'cancelled') AND updated_at < ?
		AND NOT ((status = 'sent' AND dsn_sent = 0 AND UPPER(dsn_notify) LIKE '%SUCCESS%')
		  OR (status = 'failed' AND dsn_sent = 0 AND UPPER(dsn_notify) LIKE '%FAILURE%'))
		ORDER BY updated_at, id LIMIT ?`, cutoff, limit)
	if err != nil {
		return 0, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, id := range ids {
		tx, err := db.Begin()
		if err != nil {
			return count, err
		}
		var address, recipient, sender, status string
		err = tx.QueryRow(`SELECT verp_bounce_address, rcpt_to, mail_from, status FROM outbound_queue WHERE id = ? AND status IN ('sent', 'failed', 'cancelled') AND updated_at < ?
			AND NOT ((status = 'sent' AND dsn_sent = 0 AND UPPER(dsn_notify) LIKE '%SUCCESS%')
			  OR (status = 'failed' AND dsn_sent = 0 AND UPPER(dsn_notify) LIKE '%FAILURE%'))`, id, cutoff).Scan(&address, &recipient, &sender, &status)
		if err == sql.ErrNoRows {
			_ = tx.Rollback()
			continue
		}
		if err != nil {
			_ = tx.Rollback()
			return count, err
		}
		if status != "cancelled" && db.IsVERPBounceAddress(address) {
			statement := `INSERT INTO issued_verp(address, recipient, sender) VALUES(?, ?, ?) ON CONFLICT(address) DO UPDATE SET recipient = excluded.recipient, sender = excluded.sender, archived_at = CURRENT_TIMESTAMP`
			if db.IsMySQL() {
				statement = `INSERT INTO issued_verp(address, recipient, sender) VALUES(?, ?, ?) ON DUPLICATE KEY UPDATE recipient = VALUES(recipient), sender = VALUES(sender), archived_at = CURRENT_TIMESTAMP`
			}
			if _, err := tx.Exec(statement, address, recipient, sender); err != nil {
				_ = tx.Rollback()
				return count, err
			}
		}
		result, err := tx.Exec(`DELETE FROM outbound_queue WHERE id = ? AND status IN ('sent', 'failed', 'cancelled') AND updated_at < ?
			AND NOT ((status = 'sent' AND dsn_sent = 0 AND UPPER(dsn_notify) LIKE '%SUCCESS%')
			  OR (status = 'failed' AND dsn_sent = 0 AND UPPER(dsn_notify) LIKE '%FAILURE%'))`, id, cutoff)
		if err != nil {
			_ = tx.Rollback()
			return count, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			_ = tx.Rollback()
			return count, err
		}
		if err := tx.Commit(); err != nil {
			return count, err
		}
		count += int(n)
	}
	return count, nil
}
