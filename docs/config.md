# Configuration Reference

GoMail is configured via a single `config.json` file in JSON format.

## Full Configuration Example

```json
{
  "server": {
    "hostname": "mail.example.com"
  },

  "smtp": {
    "listen_addr": ":25",
    "max_message_size": 26214400,
    "max_recipients": 100,
    "read_timeout": 60,
    "write_timeout": 60,
    "max_connections": 100,
    "ratelimit": {
      "connections_per_minute": 60,
      "messages_per_minute": 30
    }
  },

  "mail_clients": {
    "enabled": false,
    "pop3": { "enabled": true, "listen_addr": ":995" },
    "submission": { "enabled": true, "listen_addr": ":587" },
    "read_timeout": 60,
    "write_timeout": 60,
    "max_connections": 50,
    "auth_attempts_per_minute": 10
  },

  "tls": {
    "mode": "autocert",
    "cert_file": "",
    "key_file": "",
    "acme_email": "admin@example.com",
    "acme_dir": "./data/certs",
    "min_version": "1.2"
  },

  "dkim": {
    "default_selector": "mail",
    "default_algorithm": "ed25519"
  },

  "store": {
    "database": "sqlite",
    "db_path": "./data/mail.db",
    "attachments_path": "./data/attachments"
  },

  "web": {
    "listen_addr": ":443",
    "http_addr": ":80",
    "enable_tls": true,
    "session_secret": "long-random-string-min-32-chars",
    "session_max_age": 86400,
    "rate_limit_per_minute": 300,
    "trusted_proxies": [],
    "external_https": false,
    "bootstrap_admin": {
      "email": "admin@example.com",
      "password_hash": "$2a$10$..."
    }
  },

  "delivery": {
    "queue_workers": 2,
    "retry_intervals": [60, 300, 900],
    "max_retries": 3,
    "network": "tcp",
    "enable_verp": true
  },

  "dns": {
    "cache_ttl": 300
  },

  "security": {
    "csrf_key": "random-string-min-32-chars",
    "auth_enforcement": "observe",
    "quarantine_folder": "Spam"
  },

  "mail": {
    "strip_originating_ip": false
  },

  "mdn": {
    "enabled": "no",
    "mode": "manual"
  },

  "dmarc": {
    "send_reports": false
  },

  "logging": {
    "level": "info",
    "format": "text"
  }
}
```

## Section Reference

### server

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `hostname` | string | required | Primary hostname used for SMTP identity, Message-ID generation and certificates |

### smtp

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listen_addr` | string | `:25` | SMTP server bind address (port 25 for production, higher port for testing) |
| `max_message_size` | int | `26214400` | Max email size in bytes (25 MB) |
| `max_recipients` | int | `100` | Max recipients per message |
| `read_timeout` | int | `60` | Read timeout in seconds |
| `write_timeout` | int | `60` | Write timeout in seconds |
| `max_connections` | int | `100` | Max concurrent SMTP connections |
| `ratelimit.connections_per_minute` | int | `60` | Max SMTP connections per IP per minute |
| `ratelimit.messages_per_minute` | int | `30` | Max messages per IP per minute |

### tls

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | string | `autocert` | Certificate mode: `autocert` (Let's Encrypt), `manual` (provide cert files), `none` (no TLS, testing only) |
| `cert_file` | string | `` | Path to TLS certificate (required if mode=manual) |
| `key_file` | string | `` | Path to TLS private key (required if mode=manual) |
| `acme_email` | string | `` | Email for Let's Encrypt notifications (required if mode=autocert) |
| `acme_dir` | string | `./data/certs` | Directory for Let's Encrypt certificates and cache |
| `min_version` | string | `1.2` | Minimum TLS version (`1.2` or `1.3`) |

### mail_clients

Mail-client access is disabled unless `mail_clients.enabled` is explicitly set
to `true`. It cannot be enabled with `tls.mode: "none"`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Master switch for all mail-client listeners |
| `pop3.enabled` | bool | `true` when master enabled | Enable POP3 retrieval over implicit TLS |
| `pop3.listen_addr` | string | `:995` | POP3-over-TLS bind address |
| `submission.enabled` | bool | `true` when master enabled | Enable authenticated SMTP submission |
| `submission.listen_addr` | string | `:587` | Submission bind address; STARTTLS is mandatory before AUTH |
| `read_timeout` | int | `60` | Per-command/data read timeout in seconds |
| `write_timeout` | int | `60` | Response write timeout in seconds |
| `max_connections` | int | `50` | Shared concurrent POP3/submission connection limit |
| `auth_attempts_per_minute` | int | `10` | Shared authentication-attempt limit per client IP |

Use the full mailbox email address and the same bcrypt-backed account password
used by the web UI. POP3 exposes Inbox only and supports `USER`, `PASS`, `STAT`,
`LIST`, `UIDL`, `RETR`, `TOP`, `DELE`, `RSET`, and `QUIT`. Deletions are committed
to GoMail Trash only on a successful `QUIT`. SMTP submission supports `AUTH PLAIN`
and `AUTH LOGIN` only after STARTTLS, requires the envelope sender and `From`
header to match the authenticated account, strips `Bcc`, and queues mail through
the normal DKIM/delivery path.

This first client-access implementation is POP3, not IMAP: POP3 downloads the
Inbox but does not synchronize folders, flags, drafts, or sent-mail changes.
Clients needing multi-device folder synchronization should continue to use the
web UI until a complete IMAP implementation is added.

### dkim

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `default_selector` | string | `mail` | Default DKIM selector for new domains |
| `default_algorithm` | string | `ed25519` | Default DKIM algorithm: `ed25519` (faster, smaller) or `rsa` (wider compatibility) |
| `keys_dir` | string | `./keys` | Directory for storing DKIM keys (deprecated; now stored in DB) |

### store

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `database` | string | `sqlite` | Backend: `sqlite` or `mysql`; omitted keeps existing SQLite behavior |
| `db_path` | string | `./data/mail.db` | Path to SQLite database file |
| `mysql.host` | string | `127.0.0.1` | MySQL server hostname or IP |
| `mysql.port` | int | `3306` | MySQL TCP port |
| `mysql.user` | string | | Required when using MySQL |
| `mysql.password` | string | | MySQL password |
| `mysql.name` | string | | Required database name |
| `mysql.tls` | string | `false` | `true` enables certificate-verified TLS; use for remote servers |
| `attachments_path` | string | `./data/attachments` | Directory for storing email attachments |

#### MySQL example

MySQL 8.0.13 or newer is supported. Replace the `store` section with:

```json
"store": {
  "database": "mysql",
  "mysql": {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "gomail",
    "password": "replace-with-your-password",
    "name": "gomail",
    "tls": "false"
  },
  "attachments_path": "./data/attachments"
}
```

Startup connects to the selected database. If it does not exist, GoMail attempts
to create it; the user must have permission to do so. Alternatively, create an
empty database and grant the GoMail user privileges on that database beforehand.
Existing databases do not require server-wide CREATE DATABASE privileges.

GoMail creates missing tables, columns, indexes, and declared table constraints.
It preserves existing rows and extra columns. Existing column type/default changes
are not automatically applied; put these in an explicit reviewed migration.
Completed data migrations are recorded in `schema_migrations`. MySQL startup uses
an advisory lock to serialize schema upgrades across starting processes. Schema
DDL commits implicitly in MySQL, so a failed startup can leave earlier additive
steps applied; the next startup resumes by inspecting what already exists. Data
migrations must be idempotent so interrupted migrations can be retried safely.

The application user needs SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX,
and REFERENCES privileges on the application database. Explicit future migrations
may require additional privileges. Back up before upgrading.

MySQL connections use UTF-8 (`utf8mb4`), UTC timestamps, and a bounded connection
pool. Configure `max_allowed_packet` on the MySQL server large enough for complete
messages and queue inserts (for example, 64 MiB for the default 25 MiB message
limit). Attachments still live under `attachments_path`; back up that directory
along with the database. The connection password is passed through the driver
configuration and is not printed in logs.

Changing `database` selects a different backend. **It does not import existing
SQLite mail into MySQL.** An empty backend starts with the normal bootstrap-admin
flow; an existing backend reuses its accounts. Keep the old SQLite file if you
intend to switch back. See [Database development](database.md) for migration and
test instructions.

### web

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listen_addr` | string | `:443` | HTTPS bind address |
| `http_addr` | string | `:80` | HTTP bind address (for redirects and Let's Encrypt validation) |
| `enable_tls` | bool | `true` | Enable TLS for web interface |
| `session_secret` | string | `` | Reserved compatibility field; sessions currently use random opaque database tokens rather than this value |
| `session_max_age` | int | `86400` | Session cookie lifetime in seconds (24 hours) |
| `rate_limit_per_minute` | int | `300` | Per-client non-static HTTP request limit |
| `trusted_proxies` | string array | `[]` | Immediate proxy IPs/CIDRs allowed to supply forwarded client headers |
| `external_https` | bool | `false` | Treat requests from trusted proxies as externally HTTPS for cookies/HSTS |
| `bootstrap_admin.email` | string | `` | Initial admin account email |
| `bootstrap_admin.password_hash` | string | `` | Bcrypt hash of admin password (generate with `./gomail -hash-password 'password'`) |

### delivery

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `queue_workers` | int | `4` | Parallel workers processing outbound queue |
| `retry_intervals` | array | `[60,300,900,3600,14400,86400]` | Retry delays in seconds |
| `max_retries` | int | `6` | Max delivery attempts before permanent failure |
| `network` | string | `tcp` | Outbound network: `tcp`, `tcp4`, or `tcp6` |
| `enable_verp` | bool | `true` | Use per-recipient bounce envelope addresses |

### dns

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cache_ttl` | int | `300` | DNS cache TTL in seconds (5 minutes) |

### mail

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `strip_originating_ip` | bool | `false` | Omit X-Originating-IP from web-composed mail |

### mdn

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | string | `no` | Enable MDN handling: `yes` or `no` |
| `mode` | string | `manual` | `manual` prompts the user; `auto` sends automatically |

### dmarc

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `send_reports` | bool | `false` | Enable scheduled DMARC aggregate report generation/delivery |

### security

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `csrf_key` | string | `` | Secret mixed into CSRF tokens; configure a long random value |
| `auth_enforcement` | string | `observe` | Reserved compatibility setting; current routing follows discovered DMARC policy rather than this value |
| `quarantine_folder` | string | `Spam` | Reserved folder-name setting; current storage resolves the default `spam` folder type |

### logging

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `level` | string | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `format` | string | `text` | Log format: `text` or `json` |

## Authentication and Spam Routing

GoMail evaluates SPF, DKIM and DMARC for inbound messages. DMARC passes when an
aligned SPF result or an aligned passing DKIM signature exists. A DMARC failure
with discovered `p=quarantine` or `p=reject` is currently accepted and routed to
Spam; `p=none`, no policy, temporary lookup errors and successful alignment route
normally. GoMail does not currently issue SMTP 550 solely for `p=reject`.

The `security.auth_enforcement` configuration values are retained for
compatibility but are not currently used to switch this routing algorithm. Do
not document or operate them as an SMTP rejection control until the code wires
that policy explicitly.

### Mailbox Folders

Each account automatically has:

| Folder | Type | Purpose |
|--------|------|---------|
| Inbox | System | Inbound messages (default) |
| Sent | System | Outbound messages sent from this account |
| Spam | System | Quarantined emails (failed authentication) |
| Drafts | System | Autosaved and explicitly saved compositions; users can permanently delete drafts |
| Trash | System | Soft-deleted messages; users can restore or permanently delete them |
| Custom | User | User-created folders (future) |

The `quarantine_folder` config setting only affects folder name; internally it's always the `spam` type.

### Reverse proxy and TLS termination

Forwarded client-address headers are ignored unless the immediate peer is in
`web.trusted_proxies`. Values may be individual IP addresses or CIDR networks.
Set `web.external_https` when the listed proxy terminates HTTPS and the GoMail
listener itself is HTTP; this enables Secure session cookies and HSTS.

```json
"web": {
  "enable_tls": false,
  "external_https": true,
  "trusted_proxies": ["127.0.0.1", "10.20.0.0/16"]
}
```

Never add an untrusted client network or `0.0.0.0/0`: forwarded headers also
control the identity used by request and login rate limiting.

## Operations: monitoring and recovery

Monitor process availability, SMTP port 25, HTTPS, outbound queue age/failures,
disk space for the database and attachments, TLS certificate expiry, and DMARC/
TLS-RPT processing errors. Alert on sustained SMTP 4xx/5xx changes and repeated
DNSSEC/TLSA failures.

For SQLite, take a transactionally consistent database backup with the SQLite
backup command, then copy the attachments directory while message ingestion is
paused or snapshot both paths atomically. For MySQL, use a consistent database
dump/snapshot and capture the attachments directory from the same recovery point.
Encrypt backups, keep at least one off-host copy, and regularly restore into an
isolated environment. A restore is not verified until account/message counts,
attachment hashes, queue state, login, inbound SMTP, and a test outbound delivery
have all been checked.

Configuration is read from the JSON file selected by `-config`. GoMail does not
currently implement general `GOMAIL_*` environment-variable overrides.

## Generating Passwords

Generate a bcrypt password hash:

```bash
./gomail -hash-password 'your-password'
```

Copy the hash into `bootstrap_admin.password_hash` in config.json.

## Local Testing Configuration

For local testing without TLS:

```json
{
  "server": {
    "hostname": "localhost"
  },
  "smtp": {
    "listen_addr": ":2525"
  },
  "tls": {
    "mode": "none"
  },
  "web": {
    "listen_addr": ":8443",
    "http_addr": ":8080",
    "enable_tls": false,
    "session_secret": "local-test-secret",
    "bootstrap_admin": {
      "email": "admin@localhost",
      "password_hash": "$2a$10$...generated-with-hash-password..."
    }
  }
}
```

Then access at:
- Web: `http://localhost:8080`
- SMTP: `localhost:2525` (no TLS)

## Production Configuration

For production with real domain:

```json
{
  "server": {
    "hostname": "mail.example.com"
  },
  "smtp": {
    "listen_addr": ":25"
  },
  "tls": {
    "mode": "autocert",
    "acme_email": "admin@example.com",
    "acme_dir": "/etc/gomail/certs"
  },
  "store": {
    "db_path": "/var/lib/gomail/mail.db",
    "attachments_path": "/var/lib/gomail/attachments"
  },
  "web": {
    "listen_addr": ":443",
    "http_addr": ":80",
    "enable_tls": true
  },
  "delivery": {
    "queue_workers": 4
  }
}
```

Then configure DNS (see [DNS Records Guide](dns_records.md)) and run as systemd service.

## Troubleshooting Configuration

### Can't start server
- Check `listen_addr` ports aren't already in use
- Verify database file path is writable
- Check TLS certificates exist if mode=manual

### Let's Encrypt not working
- Verify domain resolves to server IP
- Ensure port 80 is open (for ACME validation)
- Check `acme_email` is valid
- Review logs for ACME errors

### Session issues
- Sessions are opaque random tokens persisted in the selected database
- Keep `security.csrf_key` stable across restarts
- Session cookie must be HttpOnly (secure setting, automatic)
- Check system time is synchronized (NTP)

### DKIM not signing
- Verify `dkim.default_algorithm` matches key type in database
- Check domain has keys generated in admin panel
- Review logs for signing errors

## Security Notes

- **session_secret** — Reserved compatibility field; not currently used to sign sessions
- **csrf_key** — Use a cryptographically random string (min 32 chars)
- **password_hash** — Always use bcrypt (never plaintext)
- **acme_email** — Use a valid email for Let's Encrypt notifications
- **TLS mode** — Never use `mode=none` in production
