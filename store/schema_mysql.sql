-- MySQL 8.0.13+ schema. Keep logical columns in sync with schema.sql.
-- Greylisting uniqueness omits recipient_domain, already contained in recipient_email.
CREATE TABLE IF NOT EXISTS domains (
    id          BIGINT PRIMARY KEY AUTO_INCREMENT,
    domain      VARCHAR(253)    NOT NULL,
    is_active   BIGINT NOT NULL DEFAULT 1,
    dkim_selector   VARCHAR(253) NOT NULL DEFAULT 'mail',
    dkim_algorithm  VARCHAR(32) NOT NULL DEFAULT 'ed25519',
    dkim_private_key LONGTEXT NOT NULL DEFAULT (''),
    dkim_public_key  LONGTEXT NOT NULL DEFAULT (''),
    require_tls     BIGINT NOT NULL DEFAULT 0,
    dane_enforcement VARCHAR(32) NOT NULL DEFAULT 'disabled',
    greylisting_enabled BIGINT NOT NULL DEFAULT 0,
    greylisting_delay_minutes BIGINT NOT NULL DEFAULT 15,
    tarpitting_enabled BIGINT NOT NULL DEFAULT 0,
    tarpitting_max_delay_seconds BIGINT NOT NULL DEFAULT 8,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;


CREATE TABLE IF NOT EXISTS accounts (
    id            BIGINT PRIMARY KEY AUTO_INCREMENT,
    domain_id     BIGINT NOT NULL,
    email         VARCHAR(254)    NOT NULL,
    display_name  VARCHAR(255)    NOT NULL DEFAULT '',
    password_hash VARCHAR(255)    NOT NULL,
    is_admin      BIGINT NOT NULL DEFAULT 0,
    is_active     BIGINT NOT NULL DEFAULT 1,
    allow_aliases BIGINT NOT NULL DEFAULT 0,
    quota_bytes   BIGINT NOT NULL DEFAULT 0,
    mailbox_used_bytes BIGINT NOT NULL DEFAULT 0,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(email),
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS domain_report_recipients (
    domain_id BIGINT PRIMARY KEY,
    account_id BIGINT NOT NULL,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS smtp_auth_policy (
    id BIGINT PRIMARY KEY,
    mode VARCHAR(16) NOT NULL DEFAULT 'both'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS smtp_user_auth_policy (
    account_id BIGINT PRIMARY KEY,
    mode VARCHAR(16) NOT NULL DEFAULT 'both',
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS smtp_app_passwords (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    account_id BIGINT NOT NULL,
    name VARCHAR(100) NOT NULL,
    secret_hash CHAR(64) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME NULL,
    UNIQUE(account_id, secret_hash),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS aliases (
    address VARCHAR(254) PRIMARY KEY,
    target_account_id BIGINT NOT NULL,
    owner_account_id BIGINT,
    FOREIGN KEY (target_account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (owner_account_id) REFERENCES accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;


CREATE TABLE IF NOT EXISTS folders (
    id          BIGINT PRIMARY KEY AUTO_INCREMENT,
    account_id  BIGINT NOT NULL,
    name        VARCHAR(255)    NOT NULL,
    folder_type VARCHAR(32)    NOT NULL DEFAULT 'custom',
    is_default  BIGINT NOT NULL DEFAULT 0,
    unread_count BIGINT NOT NULL DEFAULT 0,
    total_count  BIGINT NOT NULL DEFAULT 0,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(account_id, name),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS messages (
    id              BIGINT PRIMARY KEY AUTO_INCREMENT,
    account_id      BIGINT NOT NULL DEFAULT 0,
    folder_id       BIGINT,
    message_id      VARCHAR(998)    NOT NULL,
    direction       VARCHAR(16)    NOT NULL DEFAULT 'inbound',
    mail_from       VARCHAR(320)    NOT NULL,
    rcpt_to         LONGTEXT    NOT NULL,
    from_addr       LONGTEXT    NOT NULL DEFAULT (''),
    to_addr         LONGTEXT    NOT NULL DEFAULT (''),
    cc_addr         LONGTEXT    NOT NULL DEFAULT (''),
    reply_to        LONGTEXT    NOT NULL DEFAULT (''),
    subject         LONGTEXT    NOT NULL DEFAULT (''),
    text_body       LONGTEXT    NOT NULL DEFAULT (''),
    html_body       LONGTEXT    NOT NULL DEFAULT (''),
    raw_headers     LONGTEXT    NOT NULL DEFAULT (''),
    raw_message     LONGBLOB,
    size            BIGINT NOT NULL DEFAULT 0,
    has_attachments BIGINT NOT NULL DEFAULT 0,
    is_read         BIGINT NOT NULL DEFAULT 0,
    is_starred      BIGINT NOT NULL DEFAULT 0,
    is_deleted      BIGINT NOT NULL DEFAULT 0,
    spf_result      VARCHAR(32)    NOT NULL DEFAULT '',
    dkim_result     VARCHAR(32)    NOT NULL DEFAULT '',
    dmarc_result    VARCHAR(32)    NOT NULL DEFAULT '',
    auth_results    LONGTEXT    NOT NULL DEFAULT (''),
    mdn_requested   BIGINT NOT NULL DEFAULT 0,
    mdn_address     LONGTEXT    NOT NULL DEFAULT (''),
    mdn_sent        BIGINT NOT NULL DEFAULT 0,
    received_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS imap_mailboxes (
    folder_id       BIGINT PRIMARY KEY,
    uid_validity    BIGINT NOT NULL,
    uid_next        BIGINT NOT NULL DEFAULT 1,
    highest_modseq  BIGINT NOT NULL DEFAULT 1,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS imap_message_state (
    message_id      BIGINT PRIMARY KEY,
    folder_id       BIGINT NOT NULL,
    uid             BIGINT NOT NULL,
    modseq          BIGINT NOT NULL,
    answered        BIGINT NOT NULL DEFAULT 0,
    deleted         BIGINT NOT NULL DEFAULT 0,
    draft           BIGINT NOT NULL DEFAULT 0,
    recent          BIGINT NOT NULL DEFAULT 1,
    UNIQUE(folder_id, uid),
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS imap_keywords (
    message_id      BIGINT NOT NULL,
    keyword         VARCHAR(255) NOT NULL,
    PRIMARY KEY(message_id, keyword),
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS imap_subscriptions (
    account_id      BIGINT NOT NULL,
    folder_id       BIGINT NOT NULL,
    PRIMARY KEY(account_id, folder_id),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS imap_expunge_history (
    folder_id       BIGINT NOT NULL,
    uid             BIGINT NOT NULL,
    modseq          BIGINT NOT NULL,
    expunged_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(folder_id, uid),
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX idx_imap_state_folder_uid ON imap_message_state(folder_id, uid);
CREATE INDEX idx_imap_state_modseq ON imap_message_state(folder_id, modseq);
CREATE INDEX idx_imap_expunge_modseq ON imap_expunge_history(folder_id, modseq);

CREATE TABLE IF NOT EXISTS attachments (
    id          BIGINT PRIMARY KEY AUTO_INCREMENT,
    message_id  BIGINT NOT NULL,
    filename    LONGTEXT    NOT NULL,
    content_type LONGTEXT   NOT NULL,
    size        BIGINT NOT NULL DEFAULT 0,
    storage_path LONGTEXT   NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS outbound_queue (
    id                  BIGINT PRIMARY KEY AUTO_INCREMENT,
    message_id          BIGINT,
    origin_account_id   BIGINT NOT NULL DEFAULT -1,
    mail_from           VARCHAR(320)    NOT NULL,
    rcpt_to             LONGTEXT    NOT NULL,
    raw_message         LONGBLOB    NOT NULL,
    attempts            BIGINT NOT NULL DEFAULT 0,
    max_attempts        BIGINT NOT NULL DEFAULT 6,
    next_retry          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_error          LONGTEXT    NOT NULL DEFAULT (''),
    status              VARCHAR(32)    NOT NULL DEFAULT 'pending',
    claim_token         VARCHAR(64)    NOT NULL DEFAULT '',
    dsn_notify          VARCHAR(64)    NOT NULL DEFAULT '',
    dsn_ret             VARCHAR(16)    NOT NULL DEFAULT 'FULL',
    dsn_envid           LONGTEXT    NOT NULL DEFAULT (''),
    dsn_sent            BIGINT NOT NULL DEFAULT 0,
    dsn_attempts        BIGINT NOT NULL DEFAULT 0,
    dsn_retry_at        DATETIME NOT NULL DEFAULT '1970-01-01',
    dsn_delay_sent      BIGINT NOT NULL DEFAULT 0,
    verp_bounce_address LONGTEXT    NOT NULL DEFAULT (''),
    original_recipient  VARCHAR(320)    NOT NULL DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS outbound_queue_events (
    id          BIGINT PRIMARY KEY AUTO_INCREMENT,
    queue_id    BIGINT NOT NULL,
    event_type  VARCHAR(40) NOT NULL,
    attempt     BIGINT NOT NULL DEFAULT 0,
    smtp_code   INTEGER NOT NULL DEFAULT 0,
    detail      VARCHAR(500) NOT NULL DEFAULT '',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (queue_id) REFERENCES outbound_queue(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS outbound_queue_retention (
    id INTEGER PRIMARY KEY,
    days INTEGER NOT NULL DEFAULT 0,
    verp_days INTEGER NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS issued_verp (
    address VARCHAR(320) PRIMARY KEY,
    recipient VARCHAR(320) NOT NULL,
    sender VARCHAR(320) NOT NULL,
    archived_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS sessions (
    token      VARCHAR(64) PRIMARY KEY,
    data       LONGTEXT NOT NULL,
    expires_at DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS backup_settings (
    id              INTEGER PRIMARY KEY,
    enabled         INTEGER NOT NULL DEFAULT 0,
    directory       LONGTEXT NOT NULL,
    interval_hours  INTEGER NOT NULL DEFAULT 24,
    retention_count INTEGER NOT NULL DEFAULT 7,
    last_success_at DATETIME,
    last_path       LONGTEXT NOT NULL,
    last_error      LONGTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS report_inbox_settings (
    id              BIGINT PRIMARY KEY,
    enabled         BIGINT NOT NULL DEFAULT 0,
    account_id      BIGINT NOT NULL DEFAULT 0,
    last_message_id BIGINT NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS received_reports (
    id                BIGINT PRIMARY KEY AUTO_INCREMENT,
    account_id        BIGINT NOT NULL,
    source_message_id BIGINT NOT NULL,
    dedupe_key        CHAR(64) NOT NULL UNIQUE,
    kind              VARCHAR(16) NOT NULL,
    report_domain     VARCHAR(253) NOT NULL,
    submitter         VARCHAR(253) NOT NULL,
    report_id         VARCHAR(998) NOT NULL,
    period_start      VARCHAR(64) NOT NULL,
    period_end        VARCHAR(64) NOT NULL,
    successes         BIGINT NOT NULL DEFAULT 0,
    failures          BIGINT NOT NULL DEFAULT 0,
    payload_json      LONGTEXT NOT NULL,
    received_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_received_report_source_domain (account_id, source_message_id, kind, report_domain)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS report_inbox_failures (
    account_id BIGINT NOT NULL,
    message_id BIGINT NOT NULL,
    next_retry_unix BIGINT NOT NULL DEFAULT 0,
    attempts BIGINT NOT NULL DEFAULT 0,
    last_error VARCHAR(500) NOT NULL DEFAULT '',
    PRIMARY KEY(account_id,message_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS outbound_account_usage (
    account_id       BIGINT PRIMARY KEY,
    hour_started_at  DATETIME NOT NULL,
    hour_messages    BIGINT NOT NULL DEFAULT 0,
    hour_recipients  BIGINT NOT NULL DEFAULT 0,
    day_started_at   DATETIME NOT NULL,
    day_messages     BIGINT NOT NULL DEFAULT 0,
    day_recipients   BIGINT NOT NULL DEFAULT 0,
    suspended_until  DATETIME,
    updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;


CREATE INDEX idx_domains_domain         ON domains(domain);
CREATE INDEX idx_accounts_email         ON accounts(email);
CREATE INDEX idx_accounts_domain        ON accounts(domain_id);
CREATE INDEX idx_folders_account        ON folders(account_id);
CREATE INDEX idx_folders_type           ON folders(folder_type);
CREATE INDEX idx_messages_account       ON messages(account_id);
CREATE INDEX idx_messages_folder        ON messages(folder_id);
CREATE INDEX idx_messages_direction     ON messages(direction);
CREATE INDEX idx_messages_received_at   ON messages(received_at);
CREATE INDEX idx_messages_account_direction_page ON messages(account_id, direction, is_deleted, received_at, id);
CREATE INDEX idx_messages_folder_page ON messages(account_id, folder_id, received_at, id);
CREATE INDEX idx_messages_is_deleted    ON messages(is_deleted);
CREATE INDEX idx_messages_is_read       ON messages(is_read);
CREATE INDEX idx_messages_mail_from     ON messages(mail_from);
CREATE INDEX idx_messages_msgid         ON messages(message_id(191));
CREATE INDEX idx_attachments_message    ON attachments(message_id);
CREATE INDEX idx_queue_status           ON outbound_queue(status, next_retry);
CREATE INDEX idx_queue_verp_address     ON outbound_queue(verp_bounce_address(191));
CREATE INDEX idx_issued_verp_archived   ON issued_verp(archived_at);
CREATE INDEX idx_queue_events_queue      ON outbound_queue_events(queue_id, id);
CREATE INDEX idx_sessions_expires       ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS dmarc_feedback (
    id                  BIGINT PRIMARY KEY AUTO_INCREMENT,
    domain              VARCHAR(253) NOT NULL,
    policy_domain       VARCHAR(253) NOT NULL DEFAULT '',
    source_ip           VARCHAR(45) NOT NULL,
    envelope_from_domain LONGTEXT,
	dkim_result         VARCHAR(32),
	dkim_domain         VARCHAR(253),
	dkim_selector       VARCHAR(253),
	spf_result          VARCHAR(32),
	spf_domain          VARCHAR(253),
	spf_scope           VARCHAR(16) NOT NULL DEFAULT 'mfrom',
    dkim_aligned        BOOLEAN NOT NULL DEFAULT FALSE,
    spf_aligned         BOOLEAN NOT NULL DEFAULT FALSE,
    disposition         VARCHAR(32),
    received_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at             DATETIME
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX idx_dmarc_feedback_domain ON dmarc_feedback(domain);
CREATE INDEX idx_dmarc_feedback_policy_domain ON dmarc_feedback(policy_domain);
CREATE INDEX idx_dmarc_feedback_received ON dmarc_feedback(received_at);


CREATE TABLE IF NOT EXISTS dmarc_report_log (
    id              BIGINT PRIMARY KEY AUTO_INCREMENT,
    domain          VARCHAR(253) NOT NULL,
    last_sent_at    DATETIME NOT NULL,
    UNIQUE(domain)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;


CREATE TABLE IF NOT EXISTS tls_failures (
    id                  BIGINT PRIMARY KEY AUTO_INCREMENT,
    recipient_domain    VARCHAR(253) NOT NULL,
    failure_reason      LONGTEXT NOT NULL,
    sending_mta_ip      LONGTEXT,
    receiving_mx_hostname LONGTEXT,
    receiving_ip        LONGTEXT,
    successful          BOOLEAN NOT NULL DEFAULT FALSE,
    policy_type         VARCHAR(32) NOT NULL DEFAULT 'no-policy-found',
    policy_string       VARCHAR(4096) NOT NULL DEFAULT '[]',
    policy_domain       VARCHAR(253) NOT NULL DEFAULT '',
    mx_host_pattern     VARCHAR(4096) NOT NULL DEFAULT '[]',
    additional_information LONGTEXT,
    failure_reason_code LONGTEXT,
	attempted_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	report_attempts     INTEGER NOT NULL DEFAULT 0,
	next_report_attempt DATETIME,
	report_last_error   LONGTEXT,
	sent_at             DATETIME
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX idx_tls_failures_domain ON tls_failures(recipient_domain);
CREATE INDEX idx_tls_failures_attempted ON tls_failures(attempted_at);


CREATE TABLE IF NOT EXISTS mta_sts_policy_cache (
    domain VARCHAR(253) PRIMARY KEY,
    policy_id VARCHAR(32) NOT NULL,
    policy_json TEXT NOT NULL,
    expires_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS greylisting (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    recipient_domain VARCHAR(253) NOT NULL,
    remote_ip VARCHAR(45) NOT NULL,
    sender_email VARCHAR(254) NOT NULL,
    recipient_email VARCHAR(254) NOT NULL,
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    whitelisted_at DATETIME,
    rejected_count BIGINT NOT NULL DEFAULT 1,
    UNIQUE(remote_ip, sender_email, recipient_email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX idx_greylisting_domain ON greylisting(recipient_domain);
CREATE INDEX idx_greylisting_triplet ON greylisting(remote_ip, sender_email, recipient_email);
CREATE INDEX idx_greylisting_first_seen ON greylisting(first_seen);


CREATE TABLE IF NOT EXISTS tarpitting (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    recipient_domain VARCHAR(253) NOT NULL,
    remote_ip VARCHAR(45) NOT NULL,
    failure_count BIGINT NOT NULL DEFAULT 1,
    last_invalid_command VARCHAR(32) NOT NULL DEFAULT 'unknown',
    first_failure DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_failure DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    whitelisted_at DATETIME,
    notes LONGTEXT NOT NULL DEFAULT (''),
    UNIQUE(recipient_domain, remote_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX idx_tarpitting_domain ON tarpitting(recipient_domain);
CREATE INDEX idx_tarpitting_ip ON tarpitting(remote_ip);
CREATE INDEX idx_tarpitting_first_failure ON tarpitting(first_failure);


CREATE TABLE IF NOT EXISTS verp_bounces (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    original_recipient VARCHAR(320) NOT NULL,
    sender_email VARCHAR(254) NOT NULL,
    bounce_address LONGTEXT NOT NULL,
    bounce_type VARCHAR(32) NOT NULL DEFAULT 'unknown',
    bounce_code BIGINT,
    bounce_reason LONGTEXT NOT NULL DEFAULT (''),
    queue_entry_id BIGINT,
    bounce_received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    recorded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX idx_verp_bounces_recipient ON verp_bounces(original_recipient);
CREATE INDEX idx_verp_bounces_sender ON verp_bounces(sender_email);
CREATE INDEX idx_verp_bounces_received ON verp_bounces(bounce_received_at);
