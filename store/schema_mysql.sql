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
    quota_bytes   BIGINT NOT NULL DEFAULT 0,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(email),
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
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
    mail_from           VARCHAR(320)    NOT NULL,
    rcpt_to             LONGTEXT    NOT NULL,
    raw_message         LONGBLOB    NOT NULL,
    attempts            BIGINT NOT NULL DEFAULT 0,
    max_attempts        BIGINT NOT NULL DEFAULT 6,
    next_retry          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_error          LONGTEXT    NOT NULL DEFAULT (''),
    status              VARCHAR(32)    NOT NULL DEFAULT 'pending',
    dsn_notify          VARCHAR(64)    NOT NULL DEFAULT '',
    dsn_ret             VARCHAR(16)    NOT NULL DEFAULT 'FULL',
    dsn_envid           LONGTEXT    NOT NULL DEFAULT (''),
    dsn_sent            BIGINT NOT NULL DEFAULT 0,
    verp_bounce_address LONGTEXT    NOT NULL DEFAULT (''),
    original_recipient  VARCHAR(320)    NOT NULL DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS sessions (
    token      VARCHAR(64) PRIMARY KEY,
    data       LONGTEXT NOT NULL,
    expires_at DATETIME NOT NULL
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
CREATE INDEX idx_messages_is_deleted    ON messages(is_deleted);
CREATE INDEX idx_messages_is_read       ON messages(is_read);
CREATE INDEX idx_messages_mail_from     ON messages(mail_from);
CREATE INDEX idx_messages_msgid         ON messages(message_id(191));
CREATE INDEX idx_attachments_message    ON attachments(message_id);
CREATE INDEX idx_queue_status           ON outbound_queue(status, next_retry);
CREATE INDEX idx_sessions_expires       ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS dmarc_feedback (
    id                  BIGINT PRIMARY KEY AUTO_INCREMENT,
    domain              VARCHAR(253) NOT NULL,
    source_ip           VARCHAR(45) NOT NULL,
    envelope_from_domain LONGTEXT,
    dkim_result         VARCHAR(32),
    spf_result          VARCHAR(32),
    disposition         VARCHAR(32),
    received_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at             DATETIME
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX idx_dmarc_feedback_domain ON dmarc_feedback(domain);
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
    attempted_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at             DATETIME
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX idx_tls_failures_domain ON tls_failures(recipient_domain);
CREATE INDEX idx_tls_failures_attempted ON tls_failures(attempted_at);


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
