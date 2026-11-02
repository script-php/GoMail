package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"gomail/config"
)

var ErrOutboundLimit = errors.New("outbound account limit exceeded")

type OutboundLimitError struct {
	Reason         string
	SuspendedUntil time.Time
}

func (e *OutboundLimitError) Error() string {
	if e.SuspendedUntil.IsZero() {
		return fmt.Sprintf("%s: %s", ErrOutboundLimit, e.Reason)
	}
	return fmt.Sprintf("%s: %s until %s", ErrOutboundLimit, e.Reason, e.SuspendedUntil.UTC().Format(time.RFC3339))
}

func (e *OutboundLimitError) Unwrap() error { return ErrOutboundLimit }

type OutboundAccountUsage struct {
	AccountID      int64
	Email          string
	HourMessages   int
	HourRecipients int
	DayMessages    int
	DayRecipients  int
	SuspendedUntil *time.Time
	IsSuspended    bool
}

func (db *DB) ConfigureOutboundLimits(limits config.OutboundLimitsConfig) {
	db.outboundLimitsMu.Lock()
	db.outboundLimits = limits
	db.outboundLimitsMu.Unlock()
}

func (db *DB) OutboundLimits() config.OutboundLimitsConfig {
	db.outboundLimitsMu.RLock()
	defer db.outboundLimitsMu.RUnlock()
	return db.outboundLimits
}

func (db *DB) consumeOutboundAllowance(tx *sql.Tx, accountID int64, recipients int, now time.Time) (*OutboundLimitError, error) {
	limits := db.OutboundLimits()
	if accountID == 0 {
		return nil, nil
	}
	if !limits.Enabled {
		var suspended sql.NullTime
		err := tx.QueryRow(`SELECT suspended_until FROM outbound_account_usage WHERE account_id=?`, accountID).Scan(&suspended)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if suspended.Valid && suspended.Time.After(now.UTC()) {
			return &OutboundLimitError{Reason: "account is manually suspended", SuspendedUntil: suspended.Time.UTC()}, nil
		}
		return nil, nil
	}
	if recipients <= 0 {
		return nil, fmt.Errorf("invalid outbound recipient count")
	}
	if recipients > limits.MaxRecipientsPerMessage {
		return &OutboundLimitError{Reason: fmt.Sprintf("maximum %d recipients per message", limits.MaxRecipientsPerMessage)}, nil
	}
	now = now.UTC()
	hourStart := now.Truncate(time.Hour)
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	insert := `INSERT INTO outbound_account_usage(account_id,hour_started_at,day_started_at) VALUES(?,?,?) ON CONFLICT(account_id) DO NOTHING`
	if db.IsMySQL() {
		insert = `INSERT INTO outbound_account_usage(account_id,hour_started_at,day_started_at) VALUES(?,?,?) ON DUPLICATE KEY UPDATE account_id=account_id`
	}
	if _, err := tx.Exec(insert, accountID, databaseTime(hourStart), databaseTime(dayStart)); err != nil {
		return nil, err
	}
	query := `SELECT hour_started_at,hour_messages,hour_recipients,day_started_at,day_messages,day_recipients,suspended_until FROM outbound_account_usage WHERE account_id=?`
	if db.IsMySQL() {
		query += ` FOR UPDATE`
	}
	var storedHour, storedDay time.Time
	var hourMessages, hourRecipients, dayMessages, dayRecipients int
	var suspended sql.NullTime
	if err := tx.QueryRow(query, accountID).Scan(&storedHour, &hourMessages, &hourRecipients, &storedDay, &dayMessages, &dayRecipients, &suspended); err != nil {
		return nil, err
	}
	if suspended.Valid && suspended.Time.After(now) {
		until := suspended.Time.UTC()
		return &OutboundLimitError{Reason: "account is temporarily suspended", SuspendedUntil: until}, nil
	}
	if !storedHour.UTC().Equal(hourStart) {
		hourMessages, hourRecipients = 0, 0
	}
	if !storedDay.UTC().Equal(dayStart) {
		dayMessages, dayRecipients = 0, 0
	}
	hourMessages++
	hourRecipients += recipients
	dayMessages++
	dayRecipients += recipients
	reason := ""
	switch {
	case hourMessages > limits.MessagesPerHour:
		reason = "hourly message limit exceeded"
	case dayMessages > limits.MessagesPerDay:
		reason = "daily message limit exceeded"
	case hourRecipients > limits.RecipientsPerHour:
		reason = "hourly recipient limit exceeded"
	case dayRecipients > limits.RecipientsPerDay:
		reason = "daily recipient limit exceeded"
	}
	var until interface{}
	var limitErr *OutboundLimitError
	if reason != "" {
		suspension := now.Add(time.Duration(limits.SuspensionMinutes) * time.Minute)
		until = databaseTime(suspension)
		limitErr = &OutboundLimitError{Reason: reason, SuspendedUntil: suspension}
	}
	_, err := tx.Exec(`UPDATE outbound_account_usage SET hour_started_at=?,hour_messages=?,hour_recipients=?,day_started_at=?,day_messages=?,day_recipients=?,suspended_until=?,updated_at=CURRENT_TIMESTAMP WHERE account_id=?`,
		databaseTime(hourStart), hourMessages, hourRecipients, databaseTime(dayStart), dayMessages, dayRecipients, until, accountID)
	return limitErr, err
}

func (db *DB) ListOutboundAccountUsage(now time.Time) ([]OutboundAccountUsage, error) {
	rows, err := db.Query(`SELECT a.id,a.email,u.hour_started_at,COALESCE(u.hour_messages,0),COALESCE(u.hour_recipients,0),u.day_started_at,COALESCE(u.day_messages,0),COALESCE(u.day_recipients,0),u.suspended_until
		FROM accounts a LEFT JOIN outbound_account_usage u ON u.account_id=a.id WHERE a.is_active=1 ORDER BY a.email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []OutboundAccountUsage
	for rows.Next() {
		var usage OutboundAccountUsage
		var hourStart, dayStart, suspended sql.NullTime
		if err := rows.Scan(&usage.AccountID, &usage.Email, &hourStart, &usage.HourMessages, &usage.HourRecipients, &dayStart, &usage.DayMessages, &usage.DayRecipients, &suspended); err != nil {
			return nil, err
		}
		if !hourStart.Valid || !hourStart.Time.UTC().Equal(now.UTC().Truncate(time.Hour)) {
			usage.HourMessages, usage.HourRecipients = 0, 0
		}
		currentDay := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
		if !dayStart.Valid || !dayStart.Time.UTC().Equal(currentDay) {
			usage.DayMessages, usage.DayRecipients = 0, 0
		}
		if suspended.Valid {
			value := suspended.Time.UTC()
			usage.SuspendedUntil = &value
			usage.IsSuspended = value.After(now.UTC())
		}
		result = append(result, usage)
	}
	return result, rows.Err()
}

func (db *DB) ResetOutboundAccountUsage(accountID int64) error {
	result, err := db.Exec(`DELETE FROM outbound_account_usage WHERE account_id=?`, accountID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		var exists int
		if err := db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE id=?`, accountID).Scan(&exists); err != nil || exists != 1 {
			return sql.ErrNoRows
		}
	}
	return nil
}

func (db *DB) SetOutboundAccountSuspension(accountID int64, until *time.Time) error {
	now := time.Now().UTC()
	insert := `INSERT INTO outbound_account_usage(account_id,hour_started_at,day_started_at,suspended_until) SELECT id,?,?,? FROM accounts WHERE id=? ON CONFLICT(account_id) DO UPDATE SET suspended_until=excluded.suspended_until,updated_at=CURRENT_TIMESTAMP`
	if db.IsMySQL() {
		insert = `INSERT INTO outbound_account_usage(account_id,hour_started_at,day_started_at,suspended_until) SELECT id,?,?,? FROM accounts WHERE id=? ON DUPLICATE KEY UPDATE suspended_until=VALUES(suspended_until),updated_at=CURRENT_TIMESTAMP`
	}
	var value interface{}
	if until != nil {
		value = databaseTime(until.UTC())
	}
	result, err := db.Exec(insert, databaseTime(now.Truncate(time.Hour)), databaseTime(time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)), value, accountID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}
