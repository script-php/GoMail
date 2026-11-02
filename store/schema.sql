-- GoMail database schema

-- Domains managed by this server
CREATE TABLE IF NOT EXISTS domains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT    NOT NULL UNIQUE,
    is_active   INTEGER NOT NULL DEFAULT 1,
    dkim_selector   TEXT NOT NULL DEFAULT 'mail',
    dkim_algorithm  TEXT NOT NULL DEFAULT 'ed25519',
    dkim_private_key TEXT NOT NULL DEFAULT '',  -- PEM-encoded private key
    dkim_public_key  TEXT NOT NULL DEFAULT '',  -- Base64 public key for DNS
    require_tls     INTEGER NOT NULL DEFAULT 0,  -- 1 = fail if TLS unavailable, 0 = opportunistic TLS
    dane_enforcement TEXT NOT NULL DEFAULT 'disabled',  -- disabled, optional, required
    greylisting_enabled INTEGER NOT NULL DEFAULT 0,  -- 1 = enable greylisting, 0 = disable
    greylisting_delay_minutes INTEGER NOT NULL DEFAULT 15,  -- Minutes to wait before accepting from new sender triplet
    tarpitting_enabled INTEGER NOT NULL DEFAULT 0,  -- 1 = enable tarpitting, 0 = disable
    tarpitting_max_delay_seconds INTEGER NOT NULL DEFAULT 8,  -- Max delay in seconds for repeated failures
    created_at  DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- User accounts (each belongs to a domain)
CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id     INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    email         TEXT    NOT NULL UNIQUE,           -- full email: user@domain
    display_name  TEXT    NOT NULL DEFAULT '',
    password_hash TEXT    NOT NULL,                  -- bcrypt hash
    is_admin      INTEGER NOT NULL DEFAULT 0,        -- can manage domains/accounts
    is_active     INTEGER NOT NULL DEFAULT 1,
    allow_aliases INTEGER NOT NULL DEFAULT 0,
    quota_bytes   INTEGER NOT NULL DEFAULT 0,        -- 0 = unlimited
    mailbox_used_bytes INTEGER NOT NULL DEFAULT 0,   -- transactionally maintained logical message bytes
    created_at    DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS domain_report_recipients (
    domain_id INTEGER PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS smtp_auth_policy (
    id INTEGER PRIMARY KEY,
    mode TEXT NOT NULL DEFAULT 'both'
);

CREATE TABLE IF NOT EXISTS smtp_user_auth_policy (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    mode TEXT NOT NULL DEFAULT 'both'
);

CREATE TABLE IF NOT EXISTS smtp_app_passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    UNIQUE(account_id, secret_hash)
);

-- Local-only virtual addresses. No credentials or mailbox are created.
CREATE TABLE IF NOT EXISTS aliases (
    address TEXT PRIMARY KEY,
    target_account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    owner_account_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE
);

-- Mailbox folders for organizing messages
CREATE TABLE IF NOT EXISTS folders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,                   -- Inbox, Sent, Spam, Drafts, Trash, or custom
    folder_type TEXT    NOT NULL DEFAULT 'custom',  -- inbox, sent, spam, drafts, trash, custom
    is_default  INTEGER NOT NULL DEFAULT 0,         -- System folders
    unread_count INTEGER NOT NULL DEFAULT 0,
    total_count  INTEGER NOT NULL DEFAULT 0,
    created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(account_id, name)
);

CREATE TABLE IF NOT EXISTS messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id      INTEGER NOT NULL DEFAULT 0 REFERENCES accounts(id) ON DELETE CASCADE,
    folder_id       INTEGER REFERENCES folders(id) ON DELETE SET NULL,  -- NULL means inbox (legacy)
    message_id      TEXT    NOT NULL,                  -- RFC 5322 Message-ID
    direction       TEXT    NOT NULL DEFAULT 'inbound', -- 'inbound' or 'outbound'
    mail_from       TEXT    NOT NULL,               -- Envelope sender
    rcpt_to         TEXT    NOT NULL,               -- Envelope recipient (JSON array for multi)
    from_addr       TEXT    NOT NULL DEFAULT '',     -- From header
    to_addr         TEXT    NOT NULL DEFAULT '',     -- To header
    cc_addr         TEXT    NOT NULL DEFAULT '',     -- CC header
    reply_to        TEXT    NOT NULL DEFAULT '',     -- Reply-To header
    subject         TEXT    NOT NULL DEFAULT '',
    text_body       TEXT    NOT NULL DEFAULT '',     -- Plain text body
    html_body       TEXT    NOT NULL DEFAULT '',     -- HTML body
    raw_headers     TEXT    NOT NULL DEFAULT '',     -- Full raw headers
    raw_message     BLOB,                           -- Complete raw message
    size            INTEGER NOT NULL DEFAULT 0,     -- Message size in bytes
    has_attachments INTEGER NOT NULL DEFAULT 0,     -- Boolean
    is_read         INTEGER NOT NULL DEFAULT 0,     -- Boolean
    is_starred      INTEGER NOT NULL DEFAULT 0,     -- Boolean
    is_deleted      INTEGER NOT NULL DEFAULT 0,     -- Soft delete
    spf_result      TEXT    NOT NULL DEFAULT '',     -- pass/fail/none
    dkim_result     TEXT    NOT NULL DEFAULT '',     -- pass/fail/none
    dmarc_result    TEXT    NOT NULL DEFAULT '',     -- pass/fail/none
    auth_results    TEXT    NOT NULL DEFAULT '',     -- Authentication-Results header
    mdn_requested   INTEGER NOT NULL DEFAULT 0,     -- Boolean: sender requested read receipt
    mdn_address     TEXT    NOT NULL DEFAULT '',     -- Disposition-Notification-To address
    mdn_sent        INTEGER NOT NULL DEFAULT 0,     -- Boolean: MDN has been sent
    received_at     DATETIME NOT NULL DEFAULT (datetime('now')),
    created_at      DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- Durable IMAP synchronization state. Kept separate from webmail's Trash
-- marker because IMAP \Deleted is a pending-expunge flag, not a folder move.
CREATE TABLE IF NOT EXISTS imap_mailboxes (
    folder_id       INTEGER PRIMARY KEY REFERENCES folders(id) ON DELETE CASCADE,
    uid_validity    INTEGER NOT NULL,
    uid_next        INTEGER NOT NULL DEFAULT 1,
    highest_modseq  INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS imap_message_state (
    message_id      INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    folder_id       INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    uid             INTEGER NOT NULL,
    modseq          INTEGER NOT NULL,
    answered        INTEGER NOT NULL DEFAULT 0,
    deleted         INTEGER NOT NULL DEFAULT 0,
    draft           INTEGER NOT NULL DEFAULT 0,
    recent          INTEGER NOT NULL DEFAULT 1,
    UNIQUE(folder_id, uid)
);

CREATE TABLE IF NOT EXISTS imap_keywords (
    message_id      INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    keyword         TEXT NOT NULL,
    PRIMARY KEY(message_id, keyword)
);

CREATE TABLE IF NOT EXISTS imap_subscriptions (
    account_id      INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    folder_id       INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    PRIMARY KEY(account_id, folder_id)
);

-- Expunged UIDs are retained for QRESYNC. The folder foreign key removes the
-- history only when the mailbox itself ceases to exist.
CREATE TABLE IF NOT EXISTS imap_expunge_history (
    folder_id       INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    uid             INTEGER NOT NULL,
    modseq          INTEGER NOT NULL,
    expunged_at     DATETIME NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY(folder_id, uid)
);

CREATE TABLE IF NOT EXISTS attachments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id  INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    filename    TEXT    NOT NULL,
    content_type TEXT   NOT NULL,
    size        INTEGER NOT NULL DEFAULT 0,
    storage_path TEXT   NOT NULL,     -- Relative path in attachments dir
    created_at  DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS outbound_queue (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id          INTEGER REFERENCES messages(id) ON DELETE SET NULL,
    origin_account_id   INTEGER NOT NULL DEFAULT -1, -- 0 = system; -1 = legacy unknown
    mail_from           TEXT    NOT NULL,
    rcpt_to             TEXT    NOT NULL,      -- Single recipient per queue entry
    raw_message         BLOB    NOT NULL,      -- DKIM-signed message to send
    attempts            INTEGER NOT NULL DEFAULT 0,
    max_attempts        INTEGER NOT NULL DEFAULT 6,
    next_retry          DATETIME NOT NULL DEFAULT (datetime('now')),
    last_error          TEXT    NOT NULL DEFAULT '',
    status              TEXT    NOT NULL DEFAULT 'pending', -- pending, sending, uncertain, sent, failed, cancelled
    claim_token         TEXT    NOT NULL DEFAULT '',
    dsn_notify          TEXT    NOT NULL DEFAULT '',        -- DSN NOTIFY flags (SUCCESS,FAILURE,DELAY)
    dsn_ret             TEXT    NOT NULL DEFAULT 'FULL',    -- FULL or HDRS
    dsn_envid           TEXT    NOT NULL DEFAULT '',        -- Envelope ID for DSN reports
    dsn_sent            INTEGER NOT NULL DEFAULT 0,         -- Whether DSN was sent (boolean)
    dsn_attempts        INTEGER NOT NULL DEFAULT 0,
    dsn_retry_at        DATETIME NOT NULL DEFAULT '1970-01-01',
    dsn_delay_sent      INTEGER NOT NULL DEFAULT 0,         -- Whether a delayed DSN was sent
    verp_bounce_address TEXT    NOT NULL DEFAULT '',        -- VERP-encoded bounce address for MAIL FROM
    original_recipient  TEXT    NOT NULL DEFAULT '',        -- Original recipient for bounce tracking
    created_at          DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at          DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS outbound_queue_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    queue_id    INTEGER NOT NULL REFERENCES outbound_queue(id) ON DELETE CASCADE,
    event_type  TEXT NOT NULL,
    attempt     INTEGER NOT NULL DEFAULT 0,
    smtp_code   INTEGER NOT NULL DEFAULT 0,
    detail      TEXT NOT NULL DEFAULT '',
    created_at  DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS outbound_queue_retention (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    days INTEGER NOT NULL DEFAULT 0,
    verp_days INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS issued_verp (
    address TEXT PRIMARY KEY,
    recipient TEXT NOT NULL,
    sender TEXT NOT NULL,
    archived_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_issued_verp_archived ON issued_verp(archived_at);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    data       TEXT NOT NULL,  -- JSON session data
    expires_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS backup_settings (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    enabled         INTEGER NOT NULL DEFAULT 0,
    directory       TEXT NOT NULL DEFAULT '',
    interval_hours  INTEGER NOT NULL DEFAULT 24,
    retention_count INTEGER NOT NULL DEFAULT 7,
    last_success_at DATETIME,
    last_path       TEXT NOT NULL DEFAULT '',
    last_error      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS report_inbox_settings (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    enabled         INTEGER NOT NULL DEFAULT 0,
    account_id      INTEGER NOT NULL DEFAULT 0,
    last_message_id INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS received_reports (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id        INTEGER NOT NULL,
    source_message_id INTEGER NOT NULL,
    dedupe_key        TEXT NOT NULL UNIQUE,
    kind              TEXT NOT NULL,
    report_domain     TEXT NOT NULL,
    submitter         TEXT NOT NULL,
    report_id         TEXT NOT NULL,
    period_start      TEXT NOT NULL,
    period_end        TEXT NOT NULL,
    successes         INTEGER NOT NULL DEFAULT 0,
    failures          INTEGER NOT NULL DEFAULT 0,
    payload_json      TEXT NOT NULL,
    received_at       DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(account_id, source_message_id, kind, report_domain)
);

CREATE TABLE IF NOT EXISTS report_inbox_failures (
    account_id INTEGER NOT NULL,
    message_id INTEGER NOT NULL,
    next_retry_unix INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(account_id,message_id)
);

CREATE TABLE IF NOT EXISTS outbound_account_usage (
    account_id       INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    hour_started_at  DATETIME NOT NULL,
    hour_messages    INTEGER NOT NULL DEFAULT 0,
    hour_recipients  INTEGER NOT NULL DEFAULT 0,
    day_started_at   DATETIME NOT NULL,
    day_messages     INTEGER NOT NULL DEFAULT 0,
    day_recipients   INTEGER NOT NULL DEFAULT 0,
    suspended_until  DATETIME,
    updated_at       DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_domains_domain         ON domains(domain);
CREATE INDEX IF NOT EXISTS idx_accounts_email         ON accounts(email);
CREATE INDEX IF NOT EXISTS idx_accounts_domain        ON accounts(domain_id);
CREATE INDEX IF NOT EXISTS idx_folders_account        ON folders(account_id);
CREATE INDEX IF NOT EXISTS idx_folders_type           ON folders(folder_type);
CREATE INDEX IF NOT EXISTS idx_messages_account       ON messages(account_id);
CREATE INDEX IF NOT EXISTS idx_messages_folder        ON messages(folder_id);
CREATE INDEX IF NOT EXISTS idx_messages_direction     ON messages(direction);
CREATE INDEX IF NOT EXISTS idx_messages_received_at   ON messages(received_at);
CREATE INDEX IF NOT EXISTS idx_messages_account_direction_page ON messages(account_id, direction, is_deleted, received_at, id);
CREATE INDEX IF NOT EXISTS idx_messages_folder_page ON messages(account_id, folder_id, received_at, id);
CREATE INDEX IF NOT EXISTS idx_messages_is_deleted    ON messages(is_deleted);
CREATE INDEX IF NOT EXISTS idx_messages_is_read       ON messages(is_read);
CREATE INDEX IF NOT EXISTS idx_messages_mail_from     ON messages(mail_from);
CREATE INDEX IF NOT EXISTS idx_messages_msgid         ON messages(message_id);
CREATE INDEX IF NOT EXISTS idx_imap_state_folder_uid  ON imap_message_state(folder_id, uid);
CREATE INDEX IF NOT EXISTS idx_imap_state_modseq      ON imap_message_state(folder_id, modseq);
CREATE INDEX IF NOT EXISTS idx_imap_expunge_modseq    ON imap_expunge_history(folder_id, modseq);
CREATE INDEX IF NOT EXISTS idx_attachments_message    ON attachments(message_id);
CREATE INDEX IF NOT EXISTS idx_queue_status           ON outbound_queue(status, next_retry);
CREATE INDEX IF NOT EXISTS idx_queue_verp_address     ON outbound_queue(verp_bounce_address);
CREATE INDEX IF NOT EXISTS idx_queue_events_queue      ON outbound_queue_events(queue_id, id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires       ON sessions(expires_at);
-- DMARC feedback records for aggregate report generation (RFC 7489)
CREATE TABLE IF NOT EXISTS dmarc_feedback (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    domain              TEXT NOT NULL,  -- From header domain
    policy_domain       TEXT NOT NULL DEFAULT '', -- DMARC policy DNS owner
    source_ip           TEXT NOT NULL,  -- Remote IP
    envelope_from_domain TEXT,          -- MAIL FROM domain
	dkim_result         TEXT,           -- pass, fail, neutral, none, policy, error
	dkim_domain         TEXT,
	dkim_selector       TEXT,
	spf_result          TEXT,           -- pass, fail, neutral, none, softfail, temperror, permerror
	spf_domain          TEXT,
	spf_scope           TEXT NOT NULL DEFAULT 'mfrom',
    dkim_aligned        INTEGER NOT NULL DEFAULT 0,
    spf_aligned         INTEGER NOT NULL DEFAULT 0,
    disposition         TEXT,           -- none, quarantine, reject (from policy application)
    received_at         DATETIME NOT NULL DEFAULT (datetime('now')),
    sent_at             DATETIME        -- When this record was included in a sent report (NULL if not yet sent)
);

CREATE INDEX IF NOT EXISTS idx_dmarc_feedback_domain ON dmarc_feedback(domain);
CREATE INDEX IF NOT EXISTS idx_dmarc_feedback_policy_domain ON dmarc_feedback(policy_domain);
CREATE INDEX IF NOT EXISTS idx_dmarc_feedback_received ON dmarc_feedback(received_at);

-- Track when DMARC reports were last sent for each domain
CREATE TABLE IF NOT EXISTS dmarc_report_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain          TEXT NOT NULL UNIQUE,  -- Domain the report was for
    last_sent_at    DATETIME NOT NULL      -- When the last report was sent for this domain
);

-- TLS-RPT failure records for TLS report generation (RFC 8460)
CREATE TABLE IF NOT EXISTS tls_failures (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_domain    TEXT NOT NULL,      -- Remote domain we tried to deliver to
    failure_reason      TEXT NOT NULL,      -- tls-required, certificate-host-mismatch, certificate-expired, certificate-not-trusted, connection-refused, other
    sending_mta_ip      TEXT,               -- Our IP address
    receiving_mx_hostname TEXT,             -- Remote MX hostname
    receiving_ip        TEXT,               -- Remote MX IP
    successful          INTEGER NOT NULL DEFAULT 0,
    policy_type         TEXT NOT NULL DEFAULT 'no-policy-found',
    policy_string       TEXT NOT NULL DEFAULT '[]',
    policy_domain       TEXT NOT NULL DEFAULT '',
    mx_host_pattern     TEXT NOT NULL DEFAULT '[]',
    additional_information TEXT,
    failure_reason_code TEXT,
	attempted_at        DATETIME NOT NULL DEFAULT (datetime('now')),
	report_attempts     INTEGER NOT NULL DEFAULT 0,
	next_report_attempt DATETIME,
	report_last_error   TEXT,
	sent_at             DATETIME            -- When this record was included in a sent report (NULL if not yet sent)
);

CREATE INDEX IF NOT EXISTS idx_tls_failures_domain ON tls_failures(recipient_domain);
CREATE INDEX IF NOT EXISTS idx_tls_failures_attempted ON tls_failures(attempted_at);

-- Greylisting triplet tracking for spam mitigation
CREATE TABLE IF NOT EXISTS mta_sts_policy_cache (
    domain TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS greylisting (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_domain TEXT NOT NULL,         -- Domain this greylisting record is for
    remote_ip TEXT NOT NULL,                -- Sending server IP
    sender_email TEXT NOT NULL,             -- MAIL FROM address
    recipient_email TEXT NOT NULL,          -- RCPT TO address
    first_seen DATETIME NOT NULL DEFAULT (datetime('now')),  -- When we first saw this triplet
    whitelisted_at DATETIME,                -- When we first accepted a message from this triplet (NULL if never whitelisted)
    rejected_count INTEGER NOT NULL DEFAULT 1,  -- Number of times we rejected this triplet
    UNIQUE(remote_ip, sender_email, recipient_email)
);

CREATE INDEX IF NOT EXISTS idx_greylisting_domain ON greylisting(recipient_domain);
CREATE INDEX IF NOT EXISTS idx_greylisting_triplet ON greylisting(remote_ip, sender_email, recipient_email);
CREATE INDEX IF NOT EXISTS idx_greylisting_first_seen ON greylisting(first_seen);

-- Tarpitting: track failed SMTP commands per IP for spam mitigation
CREATE TABLE IF NOT EXISTS tarpitting (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_domain TEXT NOT NULL,         -- Domain this tarpitting record is for
    remote_ip TEXT NOT NULL,                -- Sending server IP
    failure_count INTEGER NOT NULL DEFAULT 1,  -- Number of failures from this IP
    last_invalid_command TEXT NOT NULL DEFAULT 'unknown',  -- Type of last invalid command
    first_failure DATETIME NOT NULL DEFAULT (datetime('now')),  -- When we first saw a failure
    last_failure DATETIME NOT NULL DEFAULT (datetime('now')),  -- When we last saw a failure
    whitelisted_at DATETIME,                -- When manually whitelisted (NULL = not whitelisted)
    notes TEXT NOT NULL DEFAULT '',         -- Admin notes
    UNIQUE(recipient_domain, remote_ip)
);

CREATE INDEX IF NOT EXISTS idx_tarpitting_domain ON tarpitting(recipient_domain);
CREATE INDEX IF NOT EXISTS idx_tarpitting_ip ON tarpitting(remote_ip);
CREATE INDEX IF NOT EXISTS idx_tarpitting_first_failure ON tarpitting(first_failure);

-- VERP bounce tracking for automatic recipient bounce detection
CREATE TABLE IF NOT EXISTS verp_bounces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_recipient TEXT NOT NULL,       -- Original recipient that bounced (e.g., user@external.com)
    sender_email TEXT NOT NULL,             -- Sender who sent the message (e.g., newsletter@example.com)
    bounce_address TEXT NOT NULL,           -- VERP bounce address that received the bounce
    bounce_type TEXT NOT NULL DEFAULT 'unknown',  -- permanent, temporary, unknown
    bounce_code INTEGER,                    -- SMTP error code (e.g., 550, 421)
    bounce_reason TEXT NOT NULL DEFAULT '', -- Human-readable bounce reason
    queue_entry_id INTEGER,                 -- Reference to original queue entry if available
    bounce_received_at DATETIME NOT NULL DEFAULT (datetime('now')),  -- When we received the bounce
    recorded_at DATETIME NOT NULL DEFAULT (datetime('now'))  -- When we recorded this bounce
);

CREATE INDEX IF NOT EXISTS idx_verp_bounces_recipient ON verp_bounces(original_recipient);
CREATE INDEX IF NOT EXISTS idx_verp_bounces_sender ON verp_bounces(sender_email);
CREATE INDEX IF NOT EXISTS idx_verp_bounces_received ON verp_bounces(bounce_received_at);
