-- GoMail database schema

CREATE TABLE IF NOT EXISTS messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id      TEXT    NOT NULL UNIQUE,       -- RFC 5322 Message-ID
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
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id    INTEGER REFERENCES messages(id) ON DELETE SET NULL,
    mail_from     TEXT    NOT NULL,
    rcpt_to       TEXT    NOT NULL,      -- Single recipient per queue entry
    raw_message   BLOB    NOT NULL,      -- DKIM-signed message to send
    attempts      INTEGER NOT NULL DEFAULT 0,
    max_attempts  INTEGER NOT NULL DEFAULT 6,
    next_retry    DATETIME NOT NULL DEFAULT (datetime('now')),
    last_error    TEXT    NOT NULL DEFAULT '',
    status        TEXT    NOT NULL DEFAULT 'pending', -- pending, sending, sent, failed
    created_at    DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at    DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    data       TEXT NOT NULL,  -- JSON session data
    expires_at DATETIME NOT NULL
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_messages_direction     ON messages(direction);
CREATE INDEX IF NOT EXISTS idx_messages_received_at   ON messages(received_at);
CREATE INDEX IF NOT EXISTS idx_messages_is_deleted    ON messages(is_deleted);
CREATE INDEX IF NOT EXISTS idx_messages_is_read       ON messages(is_read);
CREATE INDEX IF NOT EXISTS idx_messages_mail_from     ON messages(mail_from);
CREATE INDEX IF NOT EXISTS idx_attachments_message    ON attachments(message_id);
CREATE INDEX IF NOT EXISTS idx_queue_status           ON outbound_queue(status, next_retry);
CREATE INDEX IF NOT EXISTS idx_sessions_expires       ON sessions(expires_at);
