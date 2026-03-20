# Architecture

GoMail is a self-contained mail server written in Go. It replaces Postfix/Exim (MTA) and Dovecot (MDA) with a single binary that handles SMTP send/receive and provides a web interface.

## Design Principles

1. **Single binary** — No external dependencies besides DNS
2. **SQLite storage** — No separate database server needed
3. **Secure by default** — TLS everywhere, SPF/DKIM/DMARC, security headers
4. **Simple operations** — One config file, easy DNS setup, auto TLS

## Package Architecture

```
main.go                          Entry point, wires everything together
  │
  ├── config/                    Configuration parsing and validation
  │     └── Loaded first, shared with all packages
  │
  ├── tls/                       TLS certificate management
  │     ├── autocert.go          Let's Encrypt ACME automation
  │     ├── config.go            TLS version/cipher suite config
  │     └── dane.go              TLSA record generation
  │
  ├── store/                     SQLite database layer
  │     ├── db.go                Connection management, schema migration
  │     ├── models.go            Data structures (Message, Attachment, QueueEntry)
  │     ├── messages.go          CRUD operations + queue management
  │     └── schema.sql           Embedded database schema
  │
  ├── dns/                       DNS operations
  │     ├── mx.go                MX record lookup for outbound delivery
  │     ├── ptr.go               Reverse DNS verification
  │     └── cache.go             TTL-aware DNS cache
  │
  ├── parser/                    Email parsing
  │     ├── message.go           RFC 5322 message parsing
  │     ├── mime.go              MIME multipart handling
  │     └── attachments.go       Attachment extraction and storage
  │
  ├── auth/                      Email authentication
  │     ├── spf.go               SPF record checking
  │     ├── dkim.go              DKIM signing (outbound) and verification (inbound)
  │     ├── dmarc.go             DMARC policy evaluation
  │     └── results.go           Authentication-Results header generation
  │
  ├── smtp/                      SMTP protocol
  │     ├── inbound.go           SMTP server (receives mail)
  │     ├── outbound.go          SMTP client (sends mail to remote servers)
  │     ├── session.go           SMTP state machine (EHLO, MAIL, RCPT, DATA)
  │     └── ratelimit.go         Per-IP rate limiting
  │
  ├── delivery/                  Outbound mail queue
  │     ├── queue.go             Enqueue messages, DKIM sign before queuing
  │     ├── worker.go            Background workers that process the queue
  │     └── retry.go             Exponential backoff retry scheduling
  │
  ├── security/                  Web security
  │     ├── headers.go           HTTP security headers (CSP, HSTS, etc.)
  │     └── session.go           Session management, CSRF protection
  │
  ├── web/                       Web interface
  │     ├── server.go            HTTP routing and server setup
  │     ├── middleware.go         Logging, rate limiting, HTTPS redirect
  │     ├── handlers/            Request handlers
  │     │   ├── auth.go          Login/logout
  │     │   ├── inbox.go         List inbox/sent messages
  │     │   ├── message.go       View message, toggle star, delete
  │     │   ├── compose.go       Compose form and send (validates local recipients)
  │     │   ├── admin.go         Domain/account CRUD, DKIM key gen, DNS display
  │     │   └── helpers.go       Shared helper functions
  │     ├── templates/           HTML templates
  │     │   ├── base.html        Main layout with sidebar
  │     │   ├── inbox.html       Message list
  │     │   ├── message.html     Message detail view
  │     │   ├── compose.html     Compose form
  │     │   ├── login.html       Login form
  │     │   ├── admin_*.html     Admin panel pages
  │     │   └── base.html        Layout shared by all
  │     └── static/              CSS and JavaScript
  │
  ├── mta_sts/                   MTA-STS policy management
  └── reporting/                 DMARC and TLS report parsing
```

## Request Flow

### Inbound Mail (someone sends email to you)
```
Remote Server → TCP:25 → SMTP Inbound Server
  → Rate limit check
  → EHLO/STARTTLS negotiation
  → MAIL FROM / RCPT TO validation
  → DATA reception
  → SPF check (against connecting IP)
  → DKIM verification (against DNS public key)
  → DMARC evaluation (alignment check)
  → Message parsing (headers, body, MIME, attachments)
  → Store to SQLite
  → 250 OK response
```

### Outbound Mail (you send email to someone)
```
Web Interface → Compose → POST /send
  → Build RFC 5322 message
  → DKIM sign the message
  → Store in messages table (direction=outbound)
  → Create queue entry per recipient
  → Queue Worker picks up entry
  → MX lookup for recipient domain
  → Connect to remote MX server
  → STARTTLS negotiation
  → SMTP transaction (EHLO, MAIL, RCPT, DATA)
  → On success: mark as sent
  → On failure: schedule retry with exponential backoff
```

### Web Interface
```
Browser → TCP:443 → HTTPS Server
  → Security headers middleware
  → Session authentication check
  → Route to handler (inbox, message, compose, etc.)
  → Query SQLite
  → Render HTML template
  → Respond
```

## Security Model

- **TLS 1.2+** for all connections (SMTP STARTTLS + HTTPS)
- **Let's Encrypt** auto-provisioned certificates
- **SPF/DKIM/DMARC** for inbound verification
- **DKIM signing** for outbound messages
- **bcrypt** password hashing
- **CSRF tokens** on all forms
- **Strict CSP, HSTS, X-Frame-Options** headers
- **Rate limiting** on SMTP and web
- **Session cookies** with HttpOnly, Secure, SameSite
- **Recipient validation** — SMTP rejects mail to non-existent accounts at RCPT TO time

## Multi-Domain Architecture

GoMail supports multiple domains on a single server instance. Each domain can have multiple email accounts.

### Domain Management
- Domains stored in `domains` table with DKIM keys
- SMTP inbound checks recipient domain against active domains
- Web login accepts email addresses (format: `user@domain`)
- Admin panel CRUD for add/remove domains

### Per-Domain DKIM
- Each domain has its own Ed25519 or RSA key pair
- Keys stored encrypted in database
- Outbound delivery worker looks up domain and signs with correct key
- DKIM selector and algorithm configurable per domain

### Account Isolation
- Accounts belong to a domain (foreign key: `account.domain_id`)
- Session stores email address, not username
- Messages filtered by `account_id`, can't see other accounts' mail
- Web UI shows only current user's emails

### Database Schema

```sql
domains
  ├─ id (PRIMARY KEY)
  ├─ domain (name, unique)
  ├─ is_active
  ├─ dkim_selector
  ├─ dkim_algorithm (ed25519|rsa)
  ├─ dkim_private_key (PEM format)
  ├─ dkim_public_key (PEM format)
  └─ created_at

accounts
  ├─ id (PRIMARY KEY)
  ├─ domain_id (FOREIGN KEY → domains)
  ├─ email (unique)
  ├─ display_name
  ├─ password_hash (bcrypt)
  ├─ is_admin
  ├─ is_active
  ├─ quota_bytes
  └─ created_at

messages
  ├─ id (PRIMARY KEY)
  ├─ account_id (FOREIGN KEY → accounts)
  ├─ message_id (RFC 5322 Message-ID)
  ├─ direction (inbound|outbound)
  ├─ mail_from
  ├─ rcpt_to (JSON array)
  ├─ from_addr (parsed From: header)
  ├─ to_addr (parsed To: header)
  ├─ subject
  ├─ text_body
  ├─ html_body
  ├─ raw_headers
  ├─ raw_message (full RFC 5322)
  ├─ is_read
  ├─ is_starred
  ├─ sпf_result / dkim_result / dmarc_result
  ├─ auth_results (full header)
  └─ received_at

outbound_queue
  ├─ id (PRIMARY KEY)
  ├─ message_id (FOREIGN KEY → messages)
  ├─ mail_from
  ├─ rcpt_to
  ├─ raw_message (DKIM-signed)
  ├─ status (pending|sending|sent|failed)
  ├─ attempts
  ├─ max_attempts
  ├─ next_retry
  └─ last_error

attachments
  ├─ id (PRIMARY KEY)
  ├─ message_id (FOREIGN KEY → messages)
  ├─ filename
  ├─ content_type
  ├─ size
  ├─ file_path (on disk)
  └─ created_at
```

## Local Delivery

When sending between accounts on the same server, GoMail uses local delivery instead of SMTP:

```
Sender (admin@example.com)
    ↓
Compose form
    ↓
Recipient validation (account exists on local domain?)
    ↓
Build RFC 5322 message
    ↓
DKIM sign
    ↓
Enqueue for delivery
    ↓
Delivery worker detects local recipient
    ↓
Parse message, extract subject/body/headers
    ↓
Store directly in recipient's inbox (no SMTP)
    ↓
No internet delay, instant delivery
```

Benefits:
- **Fast** — No network latency
- **Free** — No external connections
- **Reliable** — No MX lookup failures
- **Private** — Mail never leaves your server

## Admin Panel Architecture

The admin panel (`/admin/*` routes) provides full domain/account management:

- **RequireAdmin middleware** — Checks `account.IsAdmin` flag
- **Domain management** — Add domains, generate DKIM keys, view DNS records
- **Account management** — Create accounts, assign to domains, set quotas
- **DNS helper** — Displays all required DNS records (MX, A, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, PTR)

Admin actions:
1. Add new domain → generates default DKIM selector/algorithm
2. Generate DKIM keys → creates Ed25519/RSA pair, stores in DB
3. View DNS records → admin panel displays required DNS for each record type
4. Create account → assign to domain, set password, quota, admin flag
5. Disable account → sets `is_active=0`, prevents login and mail acceptance
