package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// QueueSenderAllowed rechecks a queued user's current authority. A deleted
// account remains identifiable by the durable origin ID even after the sent
// copy is removed and message_id becomes NULL. System mail uses origin 0.
func (db *DB) QueueSenderAllowed(entry *QueueEntry, now time.Time) (bool, string, error) {
	if entry.OriginAccountID == 0 {
		// Receiver-generated DSNs use the required null reverse-path. They are
		// internal queue entries, not authenticated user submissions.
		if entry.MailFrom == "" {
			return true, "", nil
		}
		at := strings.LastIndexByte(entry.MailFrom, '@')
		if at < 0 || at == len(entry.MailFrom)-1 {
			return false, "system sender address is invalid", nil
		}
		domain, err := db.GetDomainByName(entry.MailFrom[at+1:])
		if err != nil {
			return false, "", fmt.Errorf("checking system sender domain: %w", err)
		}
		if domain == nil || !domain.IsActive {
			return false, "system sender domain is missing or disabled", nil
		}
		return true, "", nil
	}
	if entry.OriginAccountID < 0 {
		return false, "legacy queue sender cannot be identified", nil
	}
	var email string
	var accountActive, domainActive int
	var suspended sql.NullTime
	err := db.QueryRow(`SELECT a.email, a.is_active, d.is_active, u.suspended_until
		FROM accounts a JOIN domains d ON d.id = a.domain_id
		LEFT JOIN outbound_account_usage u ON u.account_id = a.id
		WHERE a.id = ?`, entry.OriginAccountID).Scan(&email, &accountActive, &domainActive, &suspended)
	if err == sql.ErrNoRows {
		return false, "sender account was deleted", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("checking queued sender: %w", err)
	}
	if accountActive == 0 || domainActive == 0 {
		return false, "sender account or domain is disabled", nil
	}
	if !strings.EqualFold(email, entry.MailFrom) {
		return false, "sender address changed after queueing", nil
	}
	if suspended.Valid && suspended.Time.After(now.UTC()) {
		return false, "sender account is suspended", nil
	}
	return true, "", nil
}
