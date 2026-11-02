# GoMail

Administrators can manage outbound delivery from **Admin → Outbound Queue**
(`/admin/queue`): inspect delivery status and errors, search envelope addresses,
retry failed entries, cancel pending/failed entries, and quarantine stale
sending entries for explicit review. See [queue operations](docs/monitoring.md)
for uncertain-delivery resolution.

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
  search, bulk actions, Trash restore and account-scoped permanent deletion.
- Webmail with Inbox, Sent, Spam, Drafts and Trash. Drafts can be created,
  resumed, autosaved and explicitly deleted, and are removed after a successful
  send. Users can update their display name and password from Settings.
- Allowlist-based HTML sanitization. Rendered HTML email is placed in a
  sandboxed iframe, isolated from the application document.
- Admin UI for domains, accounts, DKIM keys, greylisting, tarpitting and report
  data.
- Trusted-proxy-aware web rate limiting and secure-cookie handling when HTTPS
  is terminated by an explicitly configured proxy.
- `/healthz` liveness and `/readyz` readiness endpoints.
- Configurable disk-pressure reserves that temporarily stop durable writes and
  backups before a filesystem is exhausted, with metrics and admin warnings.
- Persistent per-account outbound message/recipient limits with automatic
  temporary suspension and live administrator controls.
- Optional IMAP/POP3 over TLS and authenticated SMTP submission for mail
  clients. All listeners are disabled by the master switch; IMAP additionally
  requires its explicit service switch.

## Important boundaries

- IMAP is experimental and disabled by default. Its durable mailbox/UID model,
  core IMAP4rev1 mailbox hierarchy/rename semantics, MIME body
  structures/sections, IDLE, MOVE, UIDPLUS, NAMESPACE, SPECIAL-USE, CONDSTORE,
  QRESYNC and the IMAP4rev1 SEARCH grammar are implemented. Live client
  matrices remain open. Keep it disabled for production until those tests are
  complete.
- ARC has cumulative multi-hop signing/validation, deterministic two-hop
  coverage, and selected published validation vectors. Live-intermediary
  interoperability remains open. GoMail does not add ARC to ordinary outbound messages; ARC belongs on a
  real intermediary/forwarding path.
- TLS-RPT records success/failure events, groups STS/TLSA/no-policy results,
  runs on independent daily UTC windows, and delivers to `mailto:` or HTTPS
  `rua` destinations with bounded retry state. Broader live interoperability
  coverage remains. DMARC aggregate reports retain DKIM/SPF identities and
  enforce external destination authorization.
- Admin **Received Reports** can optionally analyze DMARC XML and TLS-RPT JSON
  attachments arriving in one selected local mailbox. It is disabled by
  default, retains the original messages, and keeps a deduplicated history and
  summary dashboard. Select an existing active mailbox and publish that real
  address in the domain's reporting DNS records before enabling it. Malformed
  report messages are retried; a manual history rescan can recover old mail.
  External
  report claims are not independently verified by the dashboard.
- Admin **Aliases** maps virtual addresses on active hosted domains to existing
  active local accounts. Aliases receive mail without passwords or separate
  mailboxes; they cannot sign in. Use one for `postmaster@` or a report address
  before publishing it in DNS. External forwarding is not supported. Admins can
  optionally grant each account self-service alias creation (off by default);
  users may create up to 20 aliases on their own domain that deliver only to
  their own mailbox. Revoking permission removes those user-created aliases,
  while admin-managed aliases remain available.
- MIME charset conversion, RFC 2231 filenames and enhanced SMTP status codes
  are implemented; broad live-provider testing remains open work.
- Mailbox quotas are enforced transactionally for inbound delivery, Sent
  copies and drafts. Trash counts toward usage until permanent deletion, and a
  full mailbox is rejected temporarily without partial multi-recipient
  delivery. There is no built-in antivirus engine.

## Build and test

The module currently declares Go 1.26.1 in `go.mod`.

```bash
go build -o gomail .
go test ./auth ./backup ./config ./delivery ./dns ./logging ./mailclient ./mdn \
  ./metrics ./mta_sts ./parser ./reporting ./security ./smtp ./store ./tls ./web
go vet ./auth ./backup ./config ./delivery ./dns ./logging ./mailclient ./mdn \
  ./metrics ./mta_sts ./parser ./reporting ./security ./smtp ./store ./tls ./web
```

Browser interaction and WCAG accessibility coverage uses Playwright across
Chromium, Firefox and WebKit with axe-core. It runs against a disposable seeded
GoMail instance and does not touch production data:

The browser suite uses pnpm and the committed lockfile; install pnpm 11 before
running the targets below.

```bash
make test-e2e-install  # first run only
make test-e2e
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

After bootstrap, administrators can test and save the complete configuration
from `/admin/configuration` using a sectioned form or the raw JSON editor.
Secrets are write-only; logging and outbound-limit changes apply live, while
startup-owned settings require a restart. Each save keeps a timestamped
previous configuration beside the file.

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
    "imap": { "enabled": false, "listen_addr": ":993" },
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
| Incoming IMAP (experimental) | `mail.example.com` | 993 | SSL/TLS | Full email + account password |
| Incoming POP3 | `mail.example.com` | 995 | SSL/TLS | Full email + account password |
| Outgoing SMTP | `mail.example.com` | 587 | STARTTLS required | Full email + account password or app credential, as allowed by admin/user policy |

Submission supports AUTH PLAIN and AUTH LOGIN only after STARTTLS. It restricts
the envelope sender and From header to the authenticated account, removes Bcc,
and sends through the normal DKIM queue. Authentication attempts are rate
limited per client IP. POP3 deletion is committed to Trash only after QUIT.

When at least one client protocol and certificate-backed TLS are enabled,
Thunderbird configuration is available at `/mail/config-v1.1.xml` (also under
`/.well-known/autoconfig/mail/`) and Outlook Autodiscover at
`/autodiscover/autodiscover.xml`. Disabled protocols are never advertised.

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
An optional loopback-only Prometheus endpoint exposes bounded aggregate gauges;
see [docs/monitoring.md](docs/monitoring.md).
The CLI creates and verifies versioned offline backup archives with database,
attachment, configuration and certificate state; restores require an explicit
destructive flag. Encrypt off-host copies and regularly test restoration. Detailed guidance is in
[docs/config.md](docs/config.md#operations-monitoring-and-recovery) and
[docs/deployment.md](docs/deployment.md).
Administrators can also create verified online backups and configure automatic
interval/retention settings under **Admin → Backups**; archives remain on the
server and are not downloadable from the web interface.
