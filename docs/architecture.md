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
  │     ├── templates/           HTML templates
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
