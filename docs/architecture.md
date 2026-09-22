# Architecture

GoMail is one Go process with protocol listeners, a persistent database, an
attachment directory and background delivery/reporting workers.

## Packages

| Package | Responsibility |
|---|---|
| `config` | JSON loading, defaults and validation |
| `smtp` | Public inbound SMTP and remote outbound SMTP client |
| `mailclient` | Optional POP3-over-TLS and authenticated SMTP submission |
| `delivery` | DKIM signing, queue insertion, retry workers and local delivery |
| `auth` | SPF, DKIM, DMARC, Authentication-Results and partial ARC support |
| `dns` | MX/PTR lookup, cache and DNSSEC-authenticated TLSA lookup |
| `mta_sts` | MTA-STS discovery, parsing and cache |
| `tls` | Certificates, ACME/manual configuration and DANE matching |
| `parser` | RFC 5322/MIME parsing and attachment extraction |
| `store` | SQLite/MySQL schema, migrations and persistence |
| `web` | Webmail/admin routes, handlers and middleware |
| `security` | Sessions, CSRF and HTTP security headers |
| `reporting` | DSN, DMARC aggregate and TLS-RPT data formats/scheduling |

Dependencies are passed explicitly to servers and handlers, although storage is
a concrete `*store.DB`, not a repository interface.

## Inbound SMTP flow

```text
TCP :25
  → SMTP command/state validation and optional STARTTLS
  → recipient/account validation and DATA/BDAT limits
  → Received + SPF + DKIM + DMARC + Authentication-Results
  → parse RFC 5322/MIME
  → policy route to Inbox or Spam
  → persist raw message, parsed fields and attachments
```

ARC on received mail is inspected for diagnostics, but ARC failure is not by
itself used as an independent spam verdict. Ordinary inbound/originated messages
are not newly ARC-sealed.

## Web/submission outbound flow

```text
web compose or authenticated submission
  → validate sender/recipients and construct/accept RFC 5322 message
  → load active managed sender domain and DKIM key
  → sign message; fail closed if signing/configuration fails
  → transactionally save Sent copy and per-recipient queue entries
  → worker chooses local delivery or remote MX delivery
  → remote path evaluates MTA-STS/DANE/TLS requirements
  → success, retry, permanent failure and optional DSN state
```

Submission requires STARTTLS before AUTH, restricts both envelope sender and
From to the authenticated account, strips Bcc and uses the same queue as webmail.

## Mail-client flow

The entire `mailclient` server is disabled unless `mail_clients.enabled` is true.
POP3 is implicit TLS and exposes a stable snapshot of Inbox. One session locks a
maildrop; DELE is committed to Trash only on QUIT. Submission listens on 587 and
upgrades with STARTTLS before advertising AUTH. Both use existing bcrypt account
credentials and share per-IP authentication throttling.

IMAP is not implemented. The database already models folders and flags, but IMAP
also needs durable UID/UIDVALIDITY and synchronization/expunge semantics; those
must be designed rather than inferred from current row IDs.

## Storage

- SQLite uses WAL, foreign keys and one open connection.
- MySQL uses InnoDB/utf8mb4 and a bounded pool.
- Both schemas are maintained separately and checked for logical parity.
- Startup performs additive schema synchronization and recorded idempotent data
  migrations. Existing type/default changes require explicit migrations.
- Raw messages stay in the database; extracted attachment files are stored under
  `attachments_path`.
- Sent message plus recipient queue rows are committed together. Attachment file
  persistence is outside that transaction.

Run one application process per database. Queue claiming uses an in-process
mutex and is not a distributed multi-instance lease.

## Web security boundary

Web HTML templates never insert untrusted email HTML into the application DOM.
Email markup passes through an allowlist sanitizer and is rendered inside a
sandboxed iframe. Forwarded client IP headers are trusted only when the immediate
peer matches `web.trusted_proxies`. `web.external_https` tells session/security
middleware that an approved proxy terminates TLS.

## DANE trust boundary

TLSA is accepted only from an authenticated DNSSEC response. Usage 0/1 still
requires PKIX semantics; Usage 2/3 can establish DANE trust. Matching is applied
to the correct leaf or chain candidate. See
[dane_implementation.md](dane_implementation.md).

## Health and shutdown

- `/healthz` reports process liveness.
- `/readyz` checks readiness, including database access.
- SIGINT/SIGTERM stops SMTP, optional client services, workers and web serving.
- Operators must monitor queue/disk/certificates and perform consistent database
  plus attachment backups.
