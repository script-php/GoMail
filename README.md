# GoMail — Self-Hosted Mail Server

A lightweight, self-contained mail server written in Go that replaces Postfix, Exim, and Dovecot. Receive and send emails with a web interface, multi-domain support, and professional email authentication.

## Features

### Core Functionality
- **SMTP Inbound** — Receive emails from the internet to your domains
- **SMTP Outbound** — Send emails from your accounts using per-domain DKIM signing
- **Web Interface** — Read, compose, and manage emails via built-in web UI
- **Multiple Accounts** — Each domain can have multiple email accounts
- **Local Delivery** — Send emails between accounts on your server without going to the internet

### Multi-Domain & Multi-Account
- **Multiple Domains** — Manage `example.com`, `example.org`, etc. from one server
- **Per-Domain DKIM** — Each domain signs outbound emails with its own keys
- **Admin Panel** — Add/remove domains and accounts, manage DNS settings
- **Account Management** — Set quotas, disable accounts, configure per-user settings

### Email Authentication
- **SPF Verification** — Validates inbound emails use authorized IPs
- **DKIM Signing** — Signs outbound emails; verifies inbound signatures
- **DMARC Policy** — Evaluates alignment and applies recipient policies
- **Authentication-Results** — Full header generation for email clients
- **Per-Domain Keys** — Ed25519 or RSA keys, generated via admin panel

### Security & TLS
- **TLS Support** — Encrypted SMTP connections (`STARTTLS`)
- **Let's Encrypt** — Automatic certificate management and renewal
- **Custom Certificates** — Support for manually provided certificates
- **Local Testing Mode** — Run without TLS for development
- **Recipient Validation** — Rejects mail to non-existent accounts at SMTP time

### Storage & Database
- **SQLite** — No external database server required; embedded in the binary
- **Message Storage** — Full RFC 5322 message bodies, parsed headers, attachments
- **Queue Management** — Automatic retry for failed outbound deliveries
- **Attachment Support** — File extraction, virus scanning hooks (configurable)
- **Quota Enforcement** — Per-account storage limits (configurable)

### Web UI
- **Login System** — Secure email-based authentication with bcrypt passwords
- **Inbox/Sent Views** — Read inbound and outbound messages
- **Message Composition** — Send emails to local or remote recipients
- **Admin Dashboard** — Manage domains, accounts, DKIM keys, DNS records
- **DNS Helper** — Display all required DNS records for each domain

## Getting Started

### Prerequisites
- Linux server (Ubuntu, Debian, CentOS, or similar)
- Go 1.21+ (to build from source)
- A domain name with DNS control (for production)

### Quick Start (Local Testing)

1. **Build:**
   ```bash
   cd /path/to/GoMail
   go build -o gomail .
   ```

2. **Run:**
   ```bash
   ./gomail -config config.local.json
   ```

3. **Access:**
   - Web UI: `http://localhost:8080`
   - SMTP: `localhost:2525` (no TLS)
   - Login: `admin@localhost` / `admin` (insecure, for testing only)

4. **Create Accounts:**
   - Click the gear icon (⚙) for **Admin Panel**
   - Go to **Manage Accounts**
   - Click **+ Add Account** to create new email accounts
   - Use the web UI to send/receive emails

### Production Deployment

See [**Deployment Guide**](docs/deployment.md) for:
- Setting up with a real domain
- Configuring TLS certificates
- Running as a systemd service
- DNS record setup
- Security best practices

## Architecture

GoMail is organized into modular packages:

```
smtp/         SMTP protocol (inbound server, outbound client, session state machine)
store/        SQLite database (schema, models, CRUD operations)
auth/         Email authentication (SPF, DKIM, DMARC, results headers)
parser/       Email parsing (RFC 5322, MIME, attachments)
delivery/     Outbound queue (retry logic, local/remote delivery, DKIM signing)
web/          HTTP handlers (login, inbox, compose, admin panel)
security/     Session management (cookies, CSRF tokens)
config/       Configuration parsing (JSON format)
tls/          Certificate management (Let's Encrypt, manual certs)
```

See [**Architecture Document**](docs/architecture.md) for detailed breakdown.

## Configuration

### config.json Structure

```json
{
  "server": {
    "hostname": "mail.example.com"
  },
  "smtp": {
    "listen_addr": ":25",
    "max_message_size": 26214400,
    "max_recipients": 100,
    "ratelimit": {
      "connections_per_minute": 60,
      "messages_per_minute": 30
    }
  },
  "tls": {
    "mode": "autocert",
    "acme_email": "admin@example.com",
    "acme_dir": "./data/certs",
    "min_version": "1.2"
  },
  "web": {
    "listen_addr": ":443",
    "http_addr": ":80",
    "enable_tls": true,
    "session_secret": "long-random-string",
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
  "store": {
    "db_path": "./data/mail.db",
    "attachments_path": "./data/attachments"
  }
}
```

**Key Settings:**

| Setting | Purpose |
|---------|---------|
| `smtp.listen_addr` | SMTP server bind address (`:25` for port 25) |
| `tls.mode` | `autocert` (Let's Encrypt), `manual` (provide certs), `none` (no TLS) |
| `web.bootstrap_admin` | Initial admin account (email + bcrypt password hash) |
| `delivery.queue_workers` | Parallel workers for outbound delivery |
| `delivery.max_retries` | Failed delivery retries before permanent failure |

See [**Configuration Reference**](docs/config.md) for all options.

## DNS Setup

To receive emails from the internet, you must configure DNS records. See [**DNS Records Guide**](docs/dns_records.md) for complete instructions.

### Minimal Setup
```
example.com.              MX  10  mail.example.com.
mail.example.com.         A       203.0.113.1
example.com.              TXT     "v=spf1 mx -all"
```

### Full Setup (Recommended)
Add DKIM, DMARC, MTA-STS, TLS-RPT, and PTR records for maximum deliverability.

## Admin Panel

Access the admin panel (⚙ icon) to:

### Manage Domains
- Add/remove domains
- View DKIM configuration
- Generate new DKIM keys (Ed25519 or RSA)
- Display DNS records needed for each domain

### Manage Accounts
- Create/edit/delete email accounts
- Assign domains to accounts
- Set storage quotas
- Enable/disable accounts
- Change passwords

### View Email
- Inspect message headers
- Check SPF/DKIM/DMARC results
- Download attachments

## Web Interface URLs

| URL | Purpose |
|-----|---------|
| `/login` | Email login |
| `/inbox` | Read inbound emails |
| `/sent` | View sent emails |
| `/compose` | Compose and send emails |
| `/message/:id` | View individual message |
| `/admin/domains` | Manage domains |
| `/admin/domain/edit/:id` | Edit domain, view/generate DKIM |
| `/admin/accounts` | Manage accounts |
| `/admin/account/edit/:id` | Create/edit account |
| `/logout` | Logout |

## Security Features

### Email Validation
- **Recipient Check** — SMTP rejects mail to non-existent accounts at RCPT TO time
- **Web Validation** — Compose form checks all local recipients exist before sending
- **Account Status** — Mail rejected if account is disabled

### Authentication
- **Inbound** — SPF, DKIM, DMARC checking with result headers
- **Outbound** — Per-domain DKIM signing on all messages
- **Session** — CSRF tokens on all forms, bcrypt password hashing

### Network
- **TLS Encryption** — STARTTLS for SMTP, HTTPS for web UI
- **Rate Limiting** — Per-IP connection and message limits on SMTP
- **Max Message Size** — Configurable (default 25MB)
- **Max Recipients** — Configurable (default 100 per message)

### Data
- **SQLite WAL** — Write-Ahead Logging for crash safety
- **Foreign Keys** — Enforced referential integrity
- **Indexed Queries** — Fast lookup by email, domain, message ID

## Email Formats Supported

- **Inbound** — Full RFC 5322 parsing, MIME multipart, attachments
- **Outbound** — RFC 5322, MIME 1.0, DKIM-Signature header
- **Authentication-Results** — Full SPF/DKIM/DMARC result headers per RFC 7601

## Local Email Delivery

Send emails between your accounts without routing through the internet:

```
admin@example.com → compose → user@example.com
       (local domain)              (local domain)
              ↓
     Local delivery worker
       (no internet needed)
              ↓
    Stored in user's inbox
```

This is **instant** and **free** compared to remote delivery.

## Troubleshooting

### Check Server Logs
```bash
tail -f /var/log/gomail.log
```

### Test SMTP Connectivity
```bash
telnet mail.example.com 25
```

### Verify DNS
```bash
dig mail.example.com MX
dig example.com TXT
nslookup -type=TXT mail._domainkey.example.com
```

### Test DKIM Signature
Send a test email and inspect the headers in your inbox for:
- `DKIM-Signature:` header
- `Authentication-Results:` with `dkim=pass`

### Common Issues

| Issue | Solution |
|-------|----------|
| Can't log in | Verify bcrypt password hash in bootstrap_admin config |
| Emails bouncing | Check DNS records (MX, SPF, DKIM, PTR) |
| TLS errors | Ensure domain resolves to server IP for Let's Encrypt |
| Delivery failures | Check logs for DNS errors or network issues |
| Lost emails | Verify recipient account exists before sending |

## Development

### Build from Source
```bash
cd /path/to/GoMail
go build -o gomail .
```

### Run Tests
```bash
go test ./...
```

### Project Structure
```
main.go           Entry point
config/           Configuration
store/            Database layer
smtp/             SMTP protocol
auth/             Authentication (SPF, DKIM, DMARC)
parser/           Email parsing
delivery/         Outbound delivery
web/              HTTP handlers and templates
security/         Session, CSRF, passwords
tls/              Certificate management
```

## Limitations

- **No POP3/IMAP** — Web UI only (can be added)
- **No Mailboxes** — Single Inbox/Sent per account (can be extended)
- **No Spam Filter** — Just authentication; integrate SpamAssassin if needed
- **No Backup** — Backup your `data/mail.db` file manually
- **No Clustering** — Single-server only (no replication)

## License

GoMail is released under the MIT License. See LICENSE file.

## Contributing

Contributions welcome! Areas for improvement:
- Sieve filtering
- CalDAV/CardDAV support
- POP3/IMAP backends
- Web UI improvements
- Performance optimizations
- Database migration tools

## Support

- **Issues & Bug Reports:** GitHub Issues
- **Documentation:** See `/docs` folder
- **Email:** admin@example.com (for your own server)

---

**Ready to deploy?** Start with [**Deployment Guide**](docs/deployment.md).
