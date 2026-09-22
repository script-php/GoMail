# GoMail

GoMail is a self-hosted mail server written in Go. It receives and delivers SMTP
mail, stores mailboxes in SQLite or MySQL, provides a webmail/admin interface, and
can optionally expose POP3 plus authenticated SMTP submission to desktop and
mobile mail clients.

GoMail is under active development. Implemented protocol support is tested in
this repository, but “implemented” does not mean independently certified for
every RFC edge case or every mail provider. See [Standards status](STANDARDS_AUDIT.md)
for the known limits.

## Current features

- Inbound SMTP with STARTTLS, SIZE, PIPELINING, 8BITMIME, SMTPUTF8, DSN and
  CHUNKING/BDAT handling.
- Persistent outbound queue, retry scheduling, local delivery and per-domain
  DKIM signing. A managed sender without valid DKIM configuration is refused
  rather than silently sent unsigned.
- SPF, multi-signature DKIM and DMARC evaluation with Authentication-Results.
- MTA-STS policy discovery/enforcement and DNSSEC-authenticated DANE/TLSA
  verification for outbound SMTP.
- SQLite and MySQL storage, default mailbox folders, attachment extraction,
  search, bulk actions and soft deletion.
- Webmail with Inbox, Sent, Spam, Drafts and Trash. Drafts can be created,
  resumed and autosaved, and are removed after a successful send.
- Allowlist-based HTML sanitization. Rendered HTML email is placed in a
  sandboxed iframe, isolated from the application document.
- Admin UI for domains, accounts, DKIM keys, greylisting, tarpitting and report
  data.
- Trusted-proxy-aware web rate limiting and secure-cookie handling when HTTPS
  is terminated by an explicitly configured proxy.
- `/healthz` liveness and `/readyz` readiness endpoints.
- Optional POP3 over TLS and authenticated SMTP submission for mail clients.
  Both are disabled by default.

## Important boundaries

- IMAP is not implemented. POP3 downloads Inbox mail but does not synchronize
  folders, flags, drafts or Sent state across devices.
- ARC parsing/signing/validation code exists, but full multi-hop RFC 8617
  interoperability is not established. GoMail does not add ARC to ordinary
  outbound messages; ARC belongs on a real intermediary/forwarding path.
- TLS-RPT and DMARC aggregate-report infrastructure exists, but reporting still
  needs broader event accounting and interoperability coverage.
- MIME charset/RFC 2231 edge cases, complete SPF DNS subquery accounting,
  enhanced status codes and broad live-provider testing remain open work.
- Quota fields exist, but mailbox quota enforcement is not complete. There is
  no built-in antivirus engine.

## Build and test

The module currently declares Go 1.26.1 in `go.mod`.

```bash
go build -o gomail .
go test ./auth ./config ./delivery ./dns ./logging ./mailclient ./mdn \
  ./mta_sts ./parser ./reporting ./security ./smtp ./store ./tls ./web
go vet ./auth ./config ./delivery ./dns ./logging ./mailclient ./mdn \
  ./mta_sts ./parser ./reporting ./security ./smtp ./store ./tls ./web
```

Generate the initial bcrypt password hash with:

```bash
./gomail -hash-password 'use-a-strong-password'
```

Then configure `web.bootstrap_admin.email` and
`web.bootstrap_admin.password_hash`. Start the server with:

```bash
./gomail -config config.json
```

See [Configuration](docs/config.md), [Deployment](docs/deployment.md), and
[DNS records](docs/dns_records.md) before exposing the server to the internet.

## Minimal configuration outline

```json
{
  "server": { "hostname": "mail.example.com" },
  "smtp": {
    "listen_addr": ":25",
    "max_message_size": 26214400,
    "max_recipients": 100
  },
  "mail_clients": {
    "enabled": false,
    "pop3": { "enabled": true, "listen_addr": ":995" },
    "submission": { "enabled": true, "listen_addr": ":587" }
  },
  "tls": {
    "mode": "autocert",
    "acme_email": "admin@example.com",
    "acme_dir": "./data/certs",
    "min_version": "1.2"
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
    "session_secret": "replace-with-a-long-random-secret",
    "bootstrap_admin": {
      "email": "admin@example.com",
      "password_hash": "$2a$10$..."
    }
  }
}
```

The new mail-client listeners remain off when `mail_clients` is absent. They
cannot be enabled with `tls.mode: "none"`.

## Mail-client settings

After explicitly enabling `mail_clients` and opening the ports:

| Purpose | Host | Port | Security | Authentication |
|---|---|---:|---|---|
| Incoming POP3 | `mail.example.com` | 995 | SSL/TLS | Full email + account password |
| Outgoing SMTP | `mail.example.com` | 587 | STARTTLS required | Full email + account password |

Submission supports AUTH PLAIN and AUTH LOGIN only after STARTTLS. It restricts
the envelope sender and From header to the authenticated account, removes Bcc,
and sends through the normal DKIM queue. Authentication attempts are rate
limited per client IP. POP3 deletion is committed to Trash only after QUIT.

## DNS and deliverability

At minimum configure A/AAAA, MX, PTR, SPF, DKIM and DMARC. MTA-STS, TLS-RPT and
DNSSEC/TLSA are optional security layers. DANE is useful only when the TLSA data
is protected by a validated DNSSEC chain. The exact records and rollout advice
are in [docs/dns_records.md](docs/dns_records.md).

Deliverability also depends on IP reputation, PTR/forward-confirmed DNS, correct
DNS publication, abuse handling and message quality; passing SPF/DKIM/DMARC does
not guarantee inbox placement.

## Package map

```text
auth/         SPF, DKIM, DMARC, Authentication-Results and ARC code
config/       JSON configuration and defaults
delivery/     Queue, retry and local/remote delivery
dns/          MX, PTR, cache and authenticated TLSA lookup
mailclient/   Optional POP3-over-TLS and SMTP submission services
mta_sts/      MTA-STS discovery, parsing and cache
parser/       RFC 5322/MIME parsing and attachments
reporting/    DSN, DMARC and TLS-RPT generation/parsing
security/     Web sessions, CSRF and security headers
smtp/         Inbound SMTP session and outbound SMTP client
store/        SQLite/MySQL schemas, migrations and mailbox operations
tls/          Certificate management and DANE certificate matching
web/          Web server, middleware and handlers
```

See [Architecture](docs/architecture.md) for request and delivery flows.

## Operations

Monitor process availability, `/readyz`, SMTP/HTTPS/client ports, queue age,
delivery failures, disk space, certificate expiry and DNSSEC/TLSA failures.
Back up the database and attachment directory from one consistent recovery point,
encrypt off-host copies, and regularly test restoration. Detailed guidance is in
[docs/config.md](docs/config.md#operations-monitoring-and-recovery) and
[docs/deployment.md](docs/deployment.md).
