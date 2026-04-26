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
    quota_bytes   INTEGER NOT NULL DEFAULT 0,        -- 0 = unlimited
    created_at    DATETIME NOT NULL DEFAULT (datetime('now'))
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
    mail_from           TEXT    NOT NULL,
    rcpt_to             TEXT    NOT NULL,      -- Single recipient per queue entry
    raw_message         BLOB    NOT NULL,      -- DKIM-signed message to send
    attempts            INTEGER NOT NULL DEFAULT 0,
    max_attempts        INTEGER NOT NULL DEFAULT 6,
    next_retry          DATETIME NOT NULL DEFAULT (datetime('now')),
    last_error          TEXT    NOT NULL DEFAULT '',
    status              TEXT    NOT NULL DEFAULT 'pending', -- pending, sending, sent, failed
    dsn_notify          TEXT    NOT NULL DEFAULT '',        -- DSN NOTIFY flags (SUCCESS,FAILURE,DELAY)
    dsn_ret             TEXT    NOT NULL DEFAULT 'FULL',    -- FULL or HDRS
    dsn_envid           TEXT    NOT NULL DEFAULT '',        -- Envelope ID for DSN reports
    dsn_sent            INTEGER NOT NULL DEFAULT 0,         -- Whether DSN was sent (boolean)
    verp_bounce_address TEXT    NOT NULL DEFAULT '',        -- VERP-encoded bounce address for MAIL FROM
    original_recipient  TEXT    NOT NULL DEFAULT '',        -- Original recipient for bounce tracking
    created_at          DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at          DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    data       TEXT NOT NULL,  -- JSON session data
    expires_at DATETIME NOT NULL
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
CREATE INDEX IF NOT EXISTS idx_messages_is_deleted    ON messages(is_deleted);
CREATE INDEX IF NOT EXISTS idx_messages_is_read       ON messages(is_read);
CREATE INDEX IF NOT EXISTS idx_messages_mail_from     ON messages(mail_from);
CREATE INDEX IF NOT EXISTS idx_messages_msgid         ON messages(message_id);
CREATE INDEX IF NOT EXISTS idx_attachments_message    ON attachments(message_id);
CREATE INDEX IF NOT EXISTS idx_queue_status           ON outbound_queue(status, next_retry);
CREATE INDEX IF NOT EXISTS idx_sessions_expires       ON sessions(expires_at);
-- DMARC feedback records for aggregate report generation (RFC 7489)
CREATE TABLE IF NOT EXISTS dmarc_feedback (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    domain              TEXT NOT NULL,  -- From header domain
    source_ip           TEXT NOT NULL,  -- Remote IP
    envelope_from_domain TEXT,          -- MAIL FROM domain
    dkim_result         TEXT,           -- pass, fail, neutral, none, policy, error
    spf_result          TEXT,           -- pass, fail, neutral, none, softfail, temperror, permerror
    disposition         TEXT,           -- none, quarantine, reject (from policy application)
    received_at         DATETIME NOT NULL DEFAULT (datetime('now')),
    sent_at             DATETIME        -- When this record was included in a sent report (NULL if not yet sent)
);

CREATE INDEX IF NOT EXISTS idx_dmarc_feedback_domain ON dmarc_feedback(domain);
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
    attempted_at        DATETIME NOT NULL DEFAULT (datetime('now')),
    sent_at             DATETIME            -- When this record was included in a sent report (NULL if not yet sent)
);

CREATE INDEX IF NOT EXISTS idx_tls_failures_domain ON tls_failures(recipient_domain);
CREATE INDEX IF NOT EXISTS idx_tls_failures_attempted ON tls_failures(attempted_at);

-- Greylisting triplet tracking for spam mitigation
CREATE TABLE IF NOT EXISTS greylisting (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_domain TEXT NOT NULL,         -- Domain this greylisting record is for
    remote_ip TEXT NOT NULL,                -- Sending server IP
    sender_email TEXT NOT NULL,             -- MAIL FROM address
    recipient_email TEXT NOT NULL,          -- RCPT TO address
    first_seen DATETIME NOT NULL DEFAULT (datetime('now')),  -- When we first saw this triplet
    whitelisted_at DATETIME,                -- When we first accepted a message from this triplet (NULL if never whitelisted)
    rejected_count INTEGER NOT NULL DEFAULT 1,  -- Number of times we rejected this triplet
    UNIQUE(recipient_domain, remote_ip, sender_email, recipient_email)
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