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
    "default_algorithm": "ed25519",
    "keys_dir": "./keys"
  },

  "store": {
    "db_path": "./data/mail.db",
    "attachments_path": "./data/attachments"
  },

  "web": {
    "listen_addr": ":443",
    "http_addr": ":80",
    "enable_tls": true,
    "session_secret": "long-random-string-min-32-chars",
    "session_max_age": 86400,
    "bootstrap_admin": {
      "email": "admin@example.com",
      "password_hash": "$2a$10$..."
    }
  },

  "delivery": {
    "queue_workers": 2,
    "retry_intervals": [60, 300, 900],
    "max_retries": 3
  },

  "dns": {
    "cache_ttl": 300
  },

  "security": {
    "csrf_key": "random-string-min-32-chars"
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
| `hostname` | string | `localhost` | Primary hostname (used for Message-ID generation, certificate requests) |

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

### dkim

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `default_selector` | string | `mail` | Default DKIM selector for new domains |
| `default_algorithm` | string | `ed25519` | Default DKIM algorithm: `ed25519` (faster, smaller) or `rsa` (wider compatibility) |
| `keys_dir` | string | `./keys` | Directory for storing DKIM keys (deprecated; now stored in DB) |

### store

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `db_path` | string | `./data/mail.db` | Path to SQLite database file |
| `attachments_path` | string | `./data/attachments` | Directory for storing email attachments |

### web

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listen_addr` | string | `:443` | HTTPS bind address |
| `http_addr` | string | `:80` | HTTP bind address (for redirects and Let's Encrypt validation) |
| `enable_tls` | bool | `true` | Enable TLS for web interface |
| `session_secret` | string | `` | Secret for session cookies (min 32 chars, auto-generated if empty) |
| `session_max_age` | int | `86400` | Session cookie lifetime in seconds (24 hours) |
| `bootstrap_admin.email` | string | `` | Initial admin account email |
| `bootstrap_admin.password_hash` | string | `` | Bcrypt hash of admin password (generate with `./gomail -hash-password 'password'`) |

### delivery

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `queue_workers` | int | `2` | Parallel workers processing outbound queue |
| `retry_intervals` | array | `[60, 300, 900]` | Retry delays in seconds (1m, 5m, 15m) |
| `max_retries` | int | `3` | Max delivery attempts before permanent failure |

### dns

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cache_ttl` | int | `300` | DNS cache TTL in seconds (5 minutes) |

### security

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `csrf_key` | string | `` | Secret for CSRF token generation (min 32 chars, auto-generated if empty) |

### logging

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `level` | string | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `format` | string | `text` | Log format: `text` or `json` |

## Environment Variables

Environment variables can override config values:

```bash
export GOMAIL_SMTP_LISTEN_ADDR=":2525"
export GOMAIL_TLS_MODE="none"
export GOMAIL_WEB_SESSION_SECRET="..."
./gomail -config config.json
```

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
      "password_hash": "$2a$10$xKUZqLFPijh5HM52Di6XlOwHMc0ZRwaVOEaZGT/4RnR86dN055.J."
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
- Ensure `session_secret` is exactly same across all instances
- Session cookie must be HttpOnly (secure setting, automatic)
- Check system time is synchronized (NTP)

### DKIM not signing
- Verify `dkim.default_algorithm` matches key type in database
- Check domain has keys generated in admin panel
- Review logs for signing errors

## Security Notes

- **session_secret** — Use a cryptographically random string (min 32 chars)
- **csrf_key** — Use a cryptographically random string (min 32 chars)
- **password_hash** — Always use bcrypt (never plaintext)
- **acme_email** — Use a valid email for Let's Encrypt notifications
- **TLS mode** — Never use `mode=none` in production
