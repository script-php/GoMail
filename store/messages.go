package store

import (
	"database/sql"
	"fmt"
	"time"
)

// --- Domain CRUD ---

// CreateDomain adds a new domain.
func (db *DB) CreateDomain(d *Domain) (int64, error) {
	result, err := db.Exec(`
		INSERT INTO domains (domain, is_active, dkim_selector, dkim_algorithm, dkim_private_key, dkim_public_key, require_tls, dane_enforcement, greylisting_enabled, greylisting_delay_minutes, tarpitting_enabled, tarpitting_max_delay_seconds)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.Domain, boolToInt(d.IsActive), d.DKIMSelector, d.DKIMAlgorithm, d.DKIMPrivateKey, d.DKIMPublicKey, boolToInt(d.RequireTLS), d.DANEEnforcement, boolToInt(d.GreylistingEnabled), d.GreylistingDelayMins, boolToInt(d.TarpittingEnabled), d.TarpittingMaxDelaySecs,
	)
	if err != nil {
		return 0, fmt.Errorf("creating domain: %w", err)
	}
	return result.LastInsertId()
}

// GetDomain returns a domain by ID.
func (db *DB) GetDomain(id int64) (*Domain, error) {
	d := &Domain{}
	var isActive, requireTLS, greylistingEnabled, tarpittingEnabled int
	err := db.QueryRow(`
		SELECT id, domain, is_active, dkim_selector, dkim_algorithm, dkim_private_key, dkim_public_key, require_tls, dane_enforcement, greylisting_enabled, greylisting_delay_minutes, tarpitting_enabled, tarpitting_max_delay_seconds, created_at
		FROM domains WHERE id = ?`, id).Scan(
		&d.ID, &d.Domain, &isActive, &d.DKIMSelector, &d.DKIMAlgorithm, &d.DKIMPrivateKey, &d.DKIMPublicKey, &requireTLS, &d.DANEEnforcement, &greylistingEnabled, &d.GreylistingDelayMins, &tarpittingEnabled, &d.TarpittingMaxDelaySecs, &d.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting domain %d: %w", id, err)
	}
	d.IsActive = isActive == 1
	d.RequireTLS = requireTLS == 1
	d.GreylistingEnabled = greylistingEnabled == 1
	d.TarpittingEnabled = tarpittingEnabled == 1
	return d, nil
}

// GetDomainByName returns a domain by its domain name.
func (db *DB) GetDomainByName(domain string) (*Domain, error) {
	d := &Domain{}
	var isActive, requireTLS, greylistingEnabled, tarpittingEnabled int
	err := db.QueryRow(`
		SELECT id, domain, is_active, dkim_selector, dkim_algorithm, dkim_private_key, dkim_public_key, require_tls, dane_enforcement, greylisting_enabled, greylisting_delay_minutes, tarpitting_enabled, tarpitting_max_delay_seconds, created_at
		FROM domains WHERE domain = ?`, domain).Scan(
		&d.ID, &d.Domain, &isActive, &d.DKIMSelector, &d.DKIMAlgorithm, &d.DKIMPrivateKey, &d.DKIMPublicKey, &requireTLS, &d.DANEEnforcement, &greylistingEnabled, &d.GreylistingDelayMins, &tarpittingEnabled, &d.TarpittingMaxDelaySecs, &d.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting domain %s: %w", domain, err)
	}
	d.IsActive = isActive == 1
	d.RequireTLS = requireTLS == 1
	d.GreylistingEnabled = greylistingEnabled == 1
	d.TarpittingEnabled = tarpittingEnabled == 1
	return d, nil
}

// ListDomains returns all domains.
func (db *DB) ListDomains() ([]*Domain, error) {
	rows, err := db.Query(`
		SELECT id, domain, is_active, dkim_selector, dkim_algorithm, dkim_public_key, require_tls, dane_enforcement, greylisting_enabled, greylisting_delay_minutes, tarpitting_enabled, tarpitting_max_delay_seconds, created_at
		FROM domains ORDER BY domain`)
	if err != nil {
		return nil, fmt.Errorf("listing domains: %w", err)
	}
	defer rows.Close()

	var domains []*Domain
	for rows.Next() {
		d := &Domain{}
		var isActive, requireTLS, greylistingEnabled, tarpittingEnabled int
		if err := rows.Scan(&d.ID, &d.Domain, &isActive, &d.DKIMSelector, &d.DKIMAlgorithm, &d.DKIMPublicKey, &requireTLS, &d.DANEEnforcement, &greylistingEnabled, &d.GreylistingDelayMins, &tarpittingEnabled, &d.TarpittingMaxDelaySecs, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning domain row: %w", err)
		}
		d.IsActive = isActive == 1
		d.RequireTLS = requireTLS == 1
		d.GreylistingEnabled = greylistingEnabled == 1
		d.TarpittingEnabled = tarpittingEnabled == 1
		domains = append(domains, d)

	}
	return domains, rows.Err()
}

// UpdateDomain updates a domain.
func (db *DB) UpdateDomain(d *Domain) error {
	_, err := db.Exec(`
		UPDATE domains SET domain = ?, is_active = ?, dkim_selector = ?, dkim_algorithm = ?,
		dkim_private_key = ?, dkim_public_key = ?, require_tls = ?, dane_enforcement = ?, greylisting_enabled = ?, greylisting_delay_minutes = ?, tarpitting_enabled = ?, tarpitting_max_delay_seconds = ? WHERE id = ?`,
		d.Domain, boolToInt(d.IsActive), d.DKIMSelector, d.DKIMAlgorithm,
		d.DKIMPrivateKey, d.DKIMPublicKey, boolToInt(d.RequireTLS), d.DANEEnforcement, boolToInt(d.GreylistingEnabled), d.GreylistingDelayMins, boolToInt(d.TarpittingEnabled), d.TarpittingMaxDelaySecs, d.ID,
	)
	return err
}

// DeleteDomain removes a domain and its accounts (cascade).
func (db *DB) DeleteDomain(id int64) error {
	_, err := db.Exec(`DELETE FROM domains WHERE id = ?`, id)
	return err
}

// ListAllDomainNames returns just active domain names for SMTP routing.
func (db *DB) ListAllDomainNames() ([]string, error) {
	rows, err := db.Query(`SELECT domain FROM domains WHERE is_active = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// CountDomainAccounts returns account count for a domain.
func (db *DB) CountDomainAccounts(domainID int64) (int, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE domain_id = ?`, domainID).Scan(&count)
	return count, err
}

// GetDomainsWithFeedback returns all domains that have DMARC feedback records.
func (db *DB) GetDomainsWithFeedback() ([]*Domain, error) {
	// Get all unique domains from DMARC feedback (these are sender domains with DMARC records)
	rows, err := db.Query(`
		SELECT DISTINCT domain
		FROM dmarc_feedback
		ORDER BY domain`)
	if err != nil {
		return nil, fmt.Errorf("listing domains with feedback: %w", err)
	}
	defer rows.Close()

	var domains []*Domain
	for rows.Next() {
		var domainName string
		if err := rows.Scan(&domainName); err != nil {
			return nil, fmt.Errorf("scanning domain row: %w", err)
		}
		// Create a minimal Domain struct with just the domain name
		// (we don't need DKIM keys for report generation, just the domain)
		domains = append(domains, &Domain{
			Domain: domainName,
		})
	}
	return domains, rows.Err()
}

// --- Account CRUD ---

// CreateAccount adds a new user account.
func (db *DB) CreateAccount(a *Account) (int64, error) {
	result, err := db.Exec(`
		INSERT INTO accounts (domain_id, email, display_name, password_hash, is_admin, is_active, quota_bytes)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.DomainID, a.Email, a.DisplayName, a.PasswordHash,
		boolToInt(a.IsAdmin), boolToInt(a.IsActive), a.QuotaBytes,
	)
	if err != nil {
		return 0, fmt.Errorf("creating account: %w", err)
	}

	accountID, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	// Create default folders for the account
	if err := db.DefaultFolders(accountID); err != nil {
		// Log error but don't fail account creation
		fmt.Printf("[warn] failed to create default folders for account %d: %v\n", accountID, err)
	}

	return accountID, nil
}

// GetAccount returns an account by ID.
func (db *DB) GetAccount(id int64) (*Account, error) {
	a := &Account{}
	var isAdmin, isActive int
	err := db.QueryRow(`
		SELECT a.id, a.domain_id, a.email, a.display_name, a.password_hash,
			a.is_admin, a.is_active, a.quota_bytes, a.created_at, d.domain
		FROM accounts a JOIN domains d ON a.domain_id = d.id
		WHERE a.id = ?`, id).Scan(
		&a.ID, &a.DomainID, &a.Email, &a.DisplayName, &a.PasswordHash,
		&isAdmin, &isActive, &a.QuotaBytes, &a.CreatedAt, &a.DomainName,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting account %d: %w", id, err)
	}
	a.IsAdmin = isAdmin == 1
	a.IsActive = isActive == 1
	return a, nil
}

// GetAccountByEmail returns an account by email address.
func (db *DB) GetAccountByEmail(email string) (*Account, error) {
	a := &Account{}
	var isAdmin, isActive int
	err := db.QueryRow(`
		SELECT a.id, a.domain_id, a.email, a.display_name, a.password_hash,
			a.is_admin, a.is_active, a.quota_bytes, a.created_at, d.domain
		FROM accounts a JOIN domains d ON a.domain_id = d.id
		WHERE a.email = ? AND a.is_active = 1 AND d.is_active = 1`, email).Scan(
		&a.ID, &a.DomainID, &a.Email, &a.DisplayName, &a.PasswordHash,
		&isAdmin, &isActive, &a.QuotaBytes, &a.CreatedAt, &a.DomainName,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting account %s: %w", email, err)
	}
	a.IsAdmin = isAdmin == 1
	a.IsActive = isActive == 1
	return a, nil
}

// ListAccounts returns all accounts, optionally filtered by domain.
func (db *DB) ListAccounts(domainID int64) ([]*Account, error) {
	var rows *sql.Rows
	var err error
	if domainID > 0 {
		rows, err = db.Query(`
			SELECT a.id, a.domain_id, a.email, a.display_name, a.is_admin, a.is_active, a.quota_bytes, a.created_at, d.domain
			FROM accounts a JOIN domains d ON a.domain_id = d.id
			WHERE a.domain_id = ? ORDER BY a.email`, domainID)
	} else {
		rows, err = db.Query(`
			SELECT a.id, a.domain_id, a.email, a.display_name, a.is_admin, a.is_active, a.quota_bytes, a.created_at, d.domain
			FROM accounts a JOIN domains d ON a.domain_id = d.id
			ORDER BY a.email`)
	}
	if err != nil {
		return nil, fmt.Errorf("listing accounts: %w", err)
	}
	defer rows.Close()

	var accounts []*Account
	for rows.Next() {
		a := &Account{}
		var isAdmin, isActive int
		if err := rows.Scan(&a.ID, &a.DomainID, &a.Email, &a.DisplayName,
			&isAdmin, &isActive, &a.QuotaBytes, &a.CreatedAt, &a.DomainName); err != nil {
			return nil, fmt.Errorf("scanning account row: %w", err)
		}
		a.IsAdmin = isAdmin == 1
		a.IsActive = isActive == 1
		accounts = append(accounts, a)
	}
	return accounts, rows.Err()
}

// UpdateAccount updates an account (does not change password).
func (db *DB) UpdateAccount(a *Account) error {
	_, err := db.Exec(`
		UPDATE accounts SET domain_id = ?, email = ?, display_name = ?,
		is_admin = ?, is_active = ?, quota_bytes = ? WHERE id = ?`,
		a.DomainID, a.Email, a.DisplayName, boolToInt(a.IsAdmin),
		boolToInt(a.IsActive), a.QuotaBytes, a.ID,
	)
	return err
}

// UpdateAccountPassword updates just the password hash.
func (db *DB) UpdateAccountPassword(id int64, hash string) error {
	_, err := db.Exec(`UPDATE accounts SET password_hash = ? WHERE id = ?`, hash, id)
	return err
}

// DeleteAccount removes an account.
func (db *DB) DeleteAccount(id int64) error {
	_, err := db.Exec(`DELETE FROM accounts WHERE id = ?`, id)
	return err
}

// CountAccounts returns the total number of accounts.
func (db *DB) CountAccounts() (int, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM accounts`).Scan(&count)
	return count, err
}

// --- Message CRUD ---

// SaveMessage inserts a new message into the database.
func (db *DB) SaveMessage(m *Message) (int64, error) {
	result, err := db.Exec(`
		INSERT INTO messages (
			account_id, folder_id, message_id, direction, mail_from, rcpt_to, from_addr, to_addr,
			cc_addr, reply_to, subject, text_body, html_body, raw_headers,
			raw_message, size, has_attachments, is_read, is_starred,
			spf_result, dkim_result, dmarc_result, auth_results, mdn_requested, mdn_address, mdn_sent, received_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.AccountID, m.FolderID, m.MessageID, m.Direction, m.MailFrom, m.RcptTo, m.FromAddr, m.ToAddr,
		m.CcAddr, m.ReplyTo, m.Subject, m.TextBody, m.HTMLBody, m.RawHeaders,
		m.RawMessage, m.Size, boolToInt(m.HasAttachments), boolToInt(m.IsRead),
		boolToInt(m.IsStarred), m.SPFResult, m.DKIMResult, m.DMARCResult,
		m.AuthResults, boolToInt(m.MDNRequested), m.MDNAddress, boolToInt(m.MDNSent), m.ReceivedAt,
	)
	if err != nil {
		return 0, fmt.Errorf("saving message: %w", err)
	}
	return result.LastInsertId()
}

// GetMessage retrieves a single message by ID, scoped to an account.
func (db *DB) GetMessage(id, accountID int64) (*Message, error) {
	m := &Message{}
	var hasAttach, isRead, isStarred, isDeleted, mdnRequested, mdnSent int
	err := db.QueryRow(`
		SELECT id, account_id, folder_id, message_id, direction, mail_from, rcpt_to, from_addr, to_addr,
			cc_addr, reply_to, subject, text_body, html_body, raw_headers, raw_message,
			size, has_attachments, is_read, is_starred, is_deleted,
			spf_result, dkim_result, dmarc_result, auth_results, mdn_requested, mdn_address, mdn_sent, received_at, created_at
		FROM messages WHERE id = ? AND account_id = ?`, id, accountID).Scan(
		&m.ID, &m.AccountID, &m.FolderID, &m.MessageID, &m.Direction, &m.MailFrom, &m.RcptTo, &m.FromAddr,
		&m.ToAddr, &m.CcAddr, &m.ReplyTo, &m.Subject, &m.TextBody, &m.HTMLBody,
		&m.RawHeaders, &m.RawMessage, &m.Size, &hasAttach, &isRead, &isStarred, &isDeleted,
		&m.SPFResult, &m.DKIMResult, &m.DMARCResult, &m.AuthResults, &mdnRequested, &m.MDNAddress, &mdnSent,
		&m.ReceivedAt, &m.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting message %d: %w", id, err)
	}
	m.HasAttachments = hasAttach == 1
	m.IsRead = isRead == 1
	m.IsStarred = isStarred == 1
	m.IsDeleted = isDeleted == 1
	m.MDNRequested = mdnRequested == 1
	m.MDNSent = mdnSent == 1
	return m, nil
}

// ListMessages returns messages for the given direction, scoped to an account.
func (db *DB) ListMessages(accountID int64, direction string, limit, offset int) ([]*Message, error) {
	rows, err := db.Query(`
		SELECT id, account_id, message_id, direction, mail_from, rcpt_to, from_addr, to_addr,
			subject, size, has_attachments, is_read, is_starred,
			spf_result, dkim_result, dmarc_result, received_at
		FROM messages
		WHERE account_id = ? AND direction = ? AND is_deleted = 0
		ORDER BY received_at DESC
		LIMIT ? OFFSET ?`, accountID, direction, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("listing messages: %w", err)
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		m := &Message{}
		var hasAttach, isRead, isStarred int
		if err := rows.Scan(
			&m.ID, &m.AccountID, &m.MessageID, &m.Direction, &m.MailFrom, &m.RcptTo,
			&m.FromAddr, &m.ToAddr, &m.Subject, &m.Size,
			&hasAttach, &isRead, &isStarred,
			&m.SPFResult, &m.DKIMResult, &m.DMARCResult, &m.ReceivedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning message row: %w", err)
		}
		m.HasAttachments = hasAttach == 1
		m.IsRead = isRead == 1
		m.IsStarred = isStarred == 1
		messages = append(messages, m)
	}
	return messages, rows.Err()
}

// CountMessages returns the count of non-deleted messages for a direction, scoped to account.
func (db *DB) CountMessages(accountID int64, direction string) (int, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM messages WHERE account_id = ? AND direction = ? AND is_deleted = 0`,
		accountID, direction).Scan(&count)
	return count, err
}

// CountUnread returns the count of unread, non-deleted inbound messages for an account.
func (db *DB) CountUnread(accountID int64) (int, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM messages WHERE account_id = ? AND direction = 'inbound' AND is_read = 0 AND is_deleted = 0`,
		accountID).Scan(&count)
	return count, err
}

// MarkRead marks a message as read.
func (db *DB) MarkRead(id int64) error {
	_, err := db.Exec(`UPDATE messages SET is_read = 1 WHERE id = ?`, id)
	return err
}

// MarkStarred toggles the starred status.
func (db *DB) MarkStarred(id int64, starred bool) error {
	_, err := db.Exec(`UPDATE messages SET is_starred = ? WHERE id = ?`, boolToInt(starred), id)
	return err
}

// MarkMDNSent marks a message as having its MDN sent.
func (db *DB) MarkMDNSent(id int64) error {
	_, err := db.Exec(`UPDATE messages SET mdn_sent = 1 WHERE id = ?`, id)
	return err
}

// DeleteMessage soft-deletes a message by moving it to trash folder.
func (db *DB) DeleteMessage(id int64) error {
	// First, get the message to find the account
	m := &Message{}
	err := db.QueryRow(`SELECT account_id, folder_id FROM messages WHERE id = ?`, id).Scan(&m.AccountID, &m.FolderID)
	if err != nil {
		return fmt.Errorf("getting message for delete: %w", err)
	}

	// Get trash folder for this account
	trashFolder, err := db.GetFolderByType(m.AccountID, "trash")
	if err != nil {
		return fmt.Errorf("getting trash folder: %w", err)
	}
	if trashFolder == nil {
		return fmt.Errorf("trash folder not found for account %d", m.AccountID)
	}

	// Update counts for old folder if it exists
	if m.FolderID != nil {
		db.UpdateFolderCounts(*m.FolderID)
	}

	// Move message to trash and mark as deleted
	_, err = db.Exec(`
		UPDATE messages 
		SET folder_id = ?, is_deleted = 1 
		WHERE id = ?
	`, trashFolder.ID, id)
	if err != nil {
		return fmt.Errorf("deleting message: %w", err)
	}

	// Update trash folder counts
	db.UpdateFolderCounts(trashFolder.ID)

	return nil
}

// --- Attachment CRUD ---

// SaveAttachment inserts an attachment record.
func (db *DB) SaveAttachment(a *Attachment) (int64, error) {
	result, err := db.Exec(`
		INSERT INTO attachments (message_id, filename, content_type, size, storage_path)
		VALUES (?, ?, ?, ?, ?)`,
		a.MessageID, a.Filename, a.ContentType, a.Size, a.StoragePath,
	)
	if err != nil {
		return 0, fmt.Errorf("saving attachment: %w", err)
	}
	return result.LastInsertId()
}

// GetAttachments returns all attachments for a message.
func (db *DB) GetAttachments(messageID int64) ([]*Attachment, error) {
	rows, err := db.Query(`
		SELECT id, message_id, filename, content_type, size, storage_path, created_at
		FROM attachments WHERE message_id = ?`, messageID)
	if err != nil {
		return nil, fmt.Errorf("getting attachments: %w", err)
	}
	defer rows.Close()

	var attachments []*Attachment
	for rows.Next() {
		a := &Attachment{}
		if err := rows.Scan(&a.ID, &a.MessageID, &a.Filename, &a.ContentType,
			&a.Size, &a.StoragePath, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning attachment row: %w", err)
		}
		attachments = append(attachments, a)
	}
	return attachments, rows.Err()
}

// --- Queue CRUD ---

// sqliteTime formats a time.Time as a SQLite-compatible datetime string.
func sqliteTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05")
}

// EnqueueMessage adds a message to the outbound delivery queue.
func (db *DB) EnqueueMessage(q *QueueEntry) (int64, error) {
	result, err := db.Exec(`
		INSERT INTO outbound_queue (message_id, mail_from, rcpt_to, raw_message, max_attempts, next_retry, dsn_notify, dsn_ret, dsn_envid, verp_bounce_address, original_recipient)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		q.MessageID, q.MailFrom, q.RcptTo, q.RawMessage, q.MaxAttempts, sqliteTime(q.NextRetry), q.DSNNotify, q.DSNRet, q.DSNEnvID, q.VERPBounceAddress, q.OriginalRecipient,
	)
	if err != nil {
		return 0, fmt.Errorf("enqueueing message: %w", err)
	}
	return result.LastInsertId()
}

// GetPendingQueue returns queue entries that are ready for delivery attempt.
func (db *DB) GetPendingQueue(limit int) ([]*QueueEntry, error) {
	rows, err := db.Query(`
		SELECT id, message_id, mail_from, rcpt_to, raw_message, attempts, max_attempts,
			next_retry, last_error, status, dsn_notify, dsn_ret, dsn_envid, dsn_sent, verp_bounce_address, original_recipient, created_at, updated_at
		FROM outbound_queue
		WHERE status = 'pending' AND next_retry <= datetime('now')
		ORDER BY next_retry ASC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("reading queue: %w", err)
	}
	defer rows.Close()

	var entries []*QueueEntry
	for rows.Next() {
		q := &QueueEntry{}
		var dsnSent int
		if err := rows.Scan(&q.ID, &q.MessageID, &q.MailFrom, &q.RcptTo,
			&q.RawMessage, &q.Attempts, &q.MaxAttempts, &q.NextRetry,
			&q.LastError, &q.Status, &q.DSNNotify, &q.DSNRet, &q.DSNEnvID, &dsnSent, &q.VERPBounceAddress, &q.OriginalRecipient, &q.CreatedAt, &q.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning queue row: %w", err)
		}
		q.DSNSent = dsnSent != 0
		entries = append(entries, q)
	}
	return entries, rows.Err()
}

// UpdateQueueEntry updates a queue entry after a delivery attempt.
func (db *DB) UpdateQueueEntry(id int64, status string, attempts int, nextRetry time.Time, lastError string) error {
	_, err := db.Exec(`
		UPDATE outbound_queue
		SET status = ?, attempts = ?, next_retry = ?, last_error = ?, updated_at = datetime('now')
		WHERE id = ?`,
		status, attempts, sqliteTime(nextRetry), lastError, id,
	)
	return err
}

// RecoverStaleQueueEntries finds entries stuck in "sending" status for >30 minutes and resets them to "pending".
// This handles the case where the worker process crashed mid-delivery.
// Returns the number of entries recovered.
func (db *DB) RecoverStaleQueueEntries() (int, error) {
	// Find entries stuck in "sending" status for more than 30 minutes
	staleBefore := time.Now().UTC().Add(-30 * time.Minute)

	rows, err := db.Query(`
		SELECT id, next_retry
		FROM outbound_queue
		WHERE status = 'sending' AND updated_at < datetime(?)
	`, sqliteTime(staleBefore))
	if err != nil {
		return 0, fmt.Errorf("querying stale entries: %w", err)
	}
	defer rows.Close()

	var recovered int
	for rows.Next() {
		var id int64
		var nextRetry string
		if err := rows.Scan(&id, &nextRetry); err != nil {
			return recovered, fmt.Errorf("scanning stale entry: %w", err)
		}

		// Reset to pending with immediate retry (1 minute from now)
		newRetryTime := time.Now().UTC().Add(1 * time.Minute)
		if err := db.UpdateQueueEntry(id, "pending", 0, newRetryTime, "recovered from stale sending status"); err != nil {
			return recovered, fmt.Errorf("updating stale entry %d: %w", id, err)
		}
		recovered++
	}

	if recovered > 0 {
		// Log the recovery through fmt rather than log package to avoid circular imports
		fmt.Printf("[store] recovered %d stale queue entries from sending status\n", recovered)
	}

	return recovered, rows.Err()
}

// DeleteQueueEntry removes a completed/failed entry from the queue.
func (db *DB) DeleteQueueEntry(id int64) error {
	_, err := db.Exec(`DELETE FROM outbound_queue WHERE id = ?`, id)
	return err
}

// MarkDSNSent marks a queue entry's DSN as sent.
func (db *DB) MarkDSNSent(id int64) error {
	_, err := db.Exec(`
		UPDATE outbound_queue
		SET dsn_sent = 1, updated_at = datetime('now')
		WHERE id = ?`,
		id,
	)
	return err
}

// --- Session CRUD ---

// SaveSession stores a web session.
func (db *DB) SaveSession(token string, data string, expiresAt time.Time) error {
	_, err := db.Exec(`
		INSERT OR REPLACE INTO sessions (token, data, expires_at)
		VALUES (?, ?, ?)`, token, data, expiresAt)
	return err
}

// GetSession retrieves session data if not expired.
func (db *DB) GetSession(token string) (string, error) {
	var data string
	err := db.QueryRow(`
		SELECT data FROM sessions WHERE token = ? AND expires_at > datetime('now')`,
		token).Scan(&data)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return data, err
}

// DeleteSession removes a session.
func (db *DB) DeleteSession(token string) error {
	_, err := db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	return err
}

// CleanExpiredSessions removes all expired sessions.
func (db *DB) CleanExpiredSessions() error {
	_, err := db.Exec(`DELETE FROM sessions WHERE expires_at <= datetime('now')`)
	return err
}

// --- Greylisting ---

// GreylistStatus represents the status of a sender triplet
type GreylistStatus struct {
	IsNew         bool      // New triplet (never seen)
	IsWhitelisted bool      // Already accepted from this triplet
	FirstSeen     time.Time // When we first saw this triplet
	DelayExpired  bool      // Whether the delay has passed
}

// CheckGreylist checks if a sender triplet should be accepted or temporarily rejected.
// Returns GreylistStatus with details about the triplet.
// If not whitelisted yet and delay not expired: reject with 421
// If new: reject with 450
// Otherwise: accept and mark as whitelisted if not already
func (db *DB) CheckGreylist(recipientDomain, remoteIP, senderEmail, recipientEmail string, delayMinutes int) (*GreylistStatus, error) {
	status := &GreylistStatus{}
	var whitelistedAt sql.NullTime

	err := db.QueryRow(`
		SELECT first_seen, whitelisted_at FROM greylisting
		WHERE recipient_domain = ? AND remote_ip = ? AND sender_email = ? AND recipient_email = ?
		LIMIT 1`,
		recipientDomain, remoteIP, senderEmail, recipientEmail).Scan(&status.FirstSeen, &whitelistedAt)

	if err == sql.ErrNoRows {
		// New triplet - insert and reject
		status.IsNew = true
		_, err := db.Exec(`
			INSERT INTO greylisting (recipient_domain, remote_ip, sender_email, recipient_email, first_seen, rejected_count)
			VALUES (?, ?, ?, ?, datetime('now'), 1)`,
			recipientDomain, remoteIP, senderEmail, recipientEmail)
		if err != nil {
			return nil, fmt.Errorf("recording greylisting entry: %w", err)
		}
		return status, nil
	}
	if err != nil {
		return nil, fmt.Errorf("checking greylisting: %w", err)
	}

	// Existing triplet
	if whitelistedAt.Valid {
		status.IsWhitelisted = true
		return status, nil
	}

	// Not yet whitelisted - check if delay has passed
	elapsed := time.Since(status.FirstSeen)
	delayDuration := time.Duration(delayMinutes) * time.Minute
	if elapsed >= delayDuration {
		status.DelayExpired = true
		// Mark as whitelisted
		_, err := db.Exec(`
			UPDATE greylisting SET whitelisted_at = datetime('now')
			WHERE recipient_domain = ? AND remote_ip = ? AND sender_email = ? AND recipient_email = ?`,
			recipientDomain, remoteIP, senderEmail, recipientEmail)
		if err != nil {
			return nil, fmt.Errorf("whitelisting greylisting entry: %w", err)
		}
	}

	return status, nil
}

// CleanupGreylisting removes old greylisting entries that were never accepted (>30 days old).
// Keeps whitelisted senders in the list permanently (they are proven safe).
func (db *DB) CleanupGreylisting() error {
	_, err := db.Exec(`
		DELETE FROM greylisting
		WHERE first_seen < datetime('now', '-30 days')
		AND whitelisted_at IS NULL`)
	if err != nil {
		return fmt.Errorf("cleaning up greylisting: %w", err)
	}
	return nil
}

// GreylistEntry represents a greylisting entry for display in admin UI
type GreylistEntry struct {
	ID              int64
	RecipientDomain string
	RemoteIP        string
	SenderEmail     string
	RecipientEmail  string
	FirstSeen       time.Time
	WhitelistedAt   sql.NullTime
	RejectedCount   int
	Status          string // "NEW", "DELAYING", or "WHITELISTED"
	HoursAgo        int    // How many hours since first_seen
}

// GetGreylistingEntriesByDomain returns all greylisting entries for a domain
func (db *DB) GetGreylistingEntriesByDomain(recipientDomain string) ([]*GreylistEntry, error) {
	rows, err := db.Query(`
		SELECT id, recipient_domain, remote_ip, sender_email, recipient_email, first_seen, whitelisted_at, rejected_count
		FROM greylisting
		WHERE recipient_domain = ?
		ORDER BY first_seen DESC`, recipientDomain)
	if err != nil {
		return nil, fmt.Errorf("querying greylisting entries: %w", err)
	}
	defer rows.Close()

	var entries []*GreylistEntry
	for rows.Next() {
		e := &GreylistEntry{}
		if err := rows.Scan(&e.ID, &e.RecipientDomain, &e.RemoteIP, &e.SenderEmail,
			&e.RecipientEmail, &e.FirstSeen, &e.WhitelistedAt, &e.RejectedCount); err != nil {
			return nil, fmt.Errorf("scanning greylisting entry: %w", err)
		}

		// Calculate status and hours ago
		e.HoursAgo = int(time.Since(e.FirstSeen).Hours())
		if e.WhitelistedAt.Valid {
			e.Status = "WHITELISTED"
		} else if e.HoursAgo > 0 {
			// Assume 15 minute default delay; in real code could fetch from domain config
			if e.HoursAgo*60 >= 15 { // More than 15 minutes
				e.Status = "DELAYING"
			} else {
				e.Status = "NEW"
			}
		} else {
			e.Status = "NEW"
		}

		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// DeleteGreylistingEntry removes a specific greylisting entry
func (db *DB) DeleteGreylistingEntry(id int64) error {
	_, err := db.Exec(`DELETE FROM greylisting WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting greylisting entry: %w", err)
	}
	return nil
}

// WhitelistGreylistingEntry manually marks an entry as whitelisted
func (db *DB) WhitelistGreylistingEntry(id int64) error {
	_, err := db.Exec(`UPDATE greylisting SET whitelisted_at = datetime('now') WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("whitelisting entry: %w", err)
	}
	return nil
}

// --- Tarpitting ---

// TarpittingEntry represents a tarpitting entry for display in admin UI
type TarpittingEntry struct {
	ID                 int64
	RecipientDomain    string
	RemoteIP           string
	FailureCount       int
	LastInvalidCommand string
	FirstFailure       time.Time
	LastFailure        time.Time
	WhitelistedAt      sql.NullTime
	Notes              string
	HoursAgo           int // How many hours since first_failure
	DelaySeconds       int // Calculated delay based on failure count
}

// GetTarpittingEntriesByDomain returns all tarpitting entries for a domain
func (db *DB) GetTarpittingEntriesByDomain(recipientDomain string) ([]*TarpittingEntry, error) {
	rows, err := db.Query(`
		SELECT id, recipient_domain, remote_ip, failure_count, last_invalid_command, first_failure, last_failure, whitelisted_at, notes
		FROM tarpitting
		WHERE recipient_domain = ?
		ORDER BY last_failure DESC`, recipientDomain)
	if err != nil {
		return nil, fmt.Errorf("querying tarpitting entries: %w", err)
	}
	defer rows.Close()

	var entries []*TarpittingEntry
	for rows.Next() {
		e := &TarpittingEntry{}
		if err := rows.Scan(&e.ID, &e.RecipientDomain, &e.RemoteIP, &e.FailureCount,
			&e.LastInvalidCommand, &e.FirstFailure, &e.LastFailure, &e.WhitelistedAt, &e.Notes); err != nil {
			return nil, fmt.Errorf("scanning tarpitting row: %w", err)
		}
		// Calculate hours since first failure
		e.HoursAgo = int(time.Since(e.FirstFailure).Hours())
		// Calculate delay with default max (8 seconds for backward compatibility)
		e.DelaySeconds = calculateTarpittingDelay(e.FailureCount, 8)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// GetTarpittingEntriesByDomainWithMaxDelay returns all tarpitting entries for a domain with delays calculated using domain's max delay setting
func (db *DB) GetTarpittingEntriesByDomainWithMaxDelay(recipientDomain string, maxDelay int) ([]*TarpittingEntry, error) {
	rows, err := db.Query(`
		SELECT id, recipient_domain, remote_ip, failure_count, last_invalid_command, first_failure, last_failure, whitelisted_at, notes
		FROM tarpitting
		WHERE recipient_domain = ?
		ORDER BY last_failure DESC`, recipientDomain)
	if err != nil {
		return nil, fmt.Errorf("querying tarpitting entries: %w", err)
	}
	defer rows.Close()

	var entries []*TarpittingEntry
	for rows.Next() {
		e := &TarpittingEntry{}
		if err := rows.Scan(&e.ID, &e.RecipientDomain, &e.RemoteIP, &e.FailureCount,
			&e.LastInvalidCommand, &e.FirstFailure, &e.LastFailure, &e.WhitelistedAt, &e.Notes); err != nil {
			return nil, fmt.Errorf("scanning tarpitting row: %w", err)
		}
		// Calculate hours since first failure
		e.HoursAgo = int(time.Since(e.FirstFailure).Hours())
		// Calculate delay using domain's max delay setting
		e.DelaySeconds = calculateTarpittingDelay(e.FailureCount, maxDelay)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// calculateTarpittingDelay returns the delay in seconds based on failure count and max delay
// Uses exponential backoff: 0s, 1s, 2s, 4s, 8s, 16s, 32s, ... up to maxDelay
func calculateTarpittingDelay(failureCount, maxDelay int) int {
	if maxDelay <= 0 {
		maxDelay = 8 // Default if not set
	}
	if failureCount <= 1 {
		return 0 // Free pass on first failure
	}

	// Exponential backoff: 2^(failureCount-2) seconds
	// failureCount 2 -> 2^0 = 2
	// failureCount 3 -> 2^1 = 4
	// failureCount 4 -> 2^2 = 8
	// failureCount 5 -> 2^3 = 16
	// failureCount 6+ -> 2^4 = 30 (capped to maxDelay)
	exp := 2
	for i := 0; i < failureCount-2; i++ {
		exp *= 2
		if exp > maxDelay { // Stop early if we exceed maxDelay
			return maxDelay
		}
	}
	return minInt(exp, maxDelay)
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// IncrementTarpittingFailure increments the failure count for an IP or creates new entry
func (db *DB) IncrementTarpittingFailure(recipientDomain, remoteIP, lastInvalidCommand string) error {
	_, err := db.Exec(`
		INSERT INTO tarpitting (recipient_domain, remote_ip, failure_count, last_invalid_command, first_failure, last_failure)
		VALUES (?, ?, 1, ?, datetime('now'), datetime('now'))
		ON CONFLICT(recipient_domain, remote_ip) DO UPDATE SET
			failure_count = failure_count + 1,
			last_invalid_command = excluded.last_invalid_command,
			last_failure = datetime('now')`,
		recipientDomain, remoteIP, lastInvalidCommand)
	if err != nil {
		return fmt.Errorf("incrementing tarpitting failure: %w", err)
	}
	return nil
}

// CheckTarpitting returns the delay in seconds for this IP, or -1 if whitelisted
func (db *DB) CheckTarpitting(recipientDomain, remoteIP string) (int, error) {
	var failureCount int
	var whitelistedAt sql.NullTime
	var lastFailure time.Time

	err := db.QueryRow(`
		SELECT failure_count, whitelisted_at, last_failure
		FROM tarpitting
		WHERE recipient_domain = ? AND remote_ip = ?`,
		recipientDomain, remoteIP).Scan(&failureCount, &whitelistedAt, &lastFailure)

	if err == sql.ErrNoRows {
		return 0, nil // No entry, no delay
	}
	if err != nil {
		return 0, fmt.Errorf("checking tarpitting: %w", err)
	}

	// If whitelisted, no delay
	if whitelistedAt.Valid {
		return -1, nil
	}

	// If it's been >1 hour since last failure, reset counter
	if time.Since(lastFailure) > 1*time.Hour {
		return 0, nil
	}

	// Return calculated delay - if maxDelay not passed, use default
	// This overload kept for backward compatibility
	return calculateTarpittingDelay(failureCount, 8), nil
}

// CheckTarpittingWithMaxDelay returns the delay in seconds for this IP with domain max delay setting
func (db *DB) CheckTarpittingWithMaxDelay(recipientDomain, remoteIP string, maxDelay int) (int, error) {
	var failureCount int
	var whitelistedAt sql.NullTime
	var lastFailure time.Time

	err := db.QueryRow(`
		SELECT failure_count, whitelisted_at, last_failure
		FROM tarpitting
		WHERE recipient_domain = ? AND remote_ip = ?`,
		recipientDomain, remoteIP).Scan(&failureCount, &whitelistedAt, &lastFailure)

	if err == sql.ErrNoRows {
		return 0, nil // No entry, no delay
	}
	if err != nil {
		return 0, fmt.Errorf("checking tarpitting: %w", err)
	}

	// If whitelisted, no delay
	if whitelistedAt.Valid {
		return -1, nil
	}

	// If it's been >1 hour since last failure, reset counter
	if time.Since(lastFailure) > 1*time.Hour {
		return 0, nil
	}

	// Return calculated delay with domain's max delay setting
	return calculateTarpittingDelay(failureCount, maxDelay), nil
}

// WhitelistTarpittingEntry manually marks an entry as whitelisted
func (db *DB) WhitelistTarpittingEntry(id int64) error {
	_, err := db.Exec(`UPDATE tarpitting SET whitelisted_at = datetime('now') WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("whitelisting tarpitting entry: %w", err)
	}
	return nil
}

// DeleteTarpittingEntry removes a specific tarpitting entry
func (db *DB) DeleteTarpittingEntry(id int64) error {
	_, err := db.Exec(`DELETE FROM tarpitting WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting tarpitting entry: %w", err)
	}
	return nil
}

// CleanupTarpitting removes old tarpitting entries that were never whitelisted (>90 days old)
func (db *DB) CleanupTarpitting() error {
	_, err := db.Exec(`
		DELETE FROM tarpitting
		WHERE first_failure < datetime('now', '-90 days')
		AND whitelisted_at IS NULL`)
	if err != nil {
		return fmt.Errorf("cleaning up tarpitting: %w", err)
	}
	return nil
}

// --- Helpers ---

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
