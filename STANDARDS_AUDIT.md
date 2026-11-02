# GoMail standards and interoperability status

**Updated:** 2026-09-24
**Meaning of this document:** implementation status based on current source and
repository tests. It is not an external certification or a claim that every RFC
test vector and provider combination has passed.

## Status vocabulary

- **Implemented and tested:** meaningful automated tests cover the behavior.
- **Implemented, coverage incomplete:** code exists, but edge/interoperability
  coverage remains.
- **Partial:** useful subset exists and known requirements remain.
- **Not implemented:** no supported production path exists.

## SMTP transport

| Area | Status | Notes |
|---|---|---|
| RFC 5321 inbound SMTP | Implemented, coverage incomplete | EHLO/HELO, MAIL, RCPT, DATA, RSET, NOOP, VRFY and QUIT with sequencing and limits |
| STARTTLS (RFC 3207) | Implemented and tested | State and greeting knowledge reset after TLS; a fresh EHLO/HELO is required |
| SIZE (RFC 1870) | Implemented and tested | Declared and received sizes bounded |
| 8BITMIME (RFC 6152) | Implemented and tested | Inbound BODY validation and outbound capability enforcement |
| SMTPUTF8 (RFC 6531) | Implemented and tested | Correctly attached to MAIL FROM, not RCPT TO; peer support required outbound |
| CHUNKING/BDAT (RFC 3030) | Implemented and tested | Size/overflow and LAST behavior covered; broad client interop remains |
| PIPELINING (RFC 2920) | Implemented by sequential command loop | Advertised; no parallel command execution is required by the extension |
| DSN extension (RFC 3461) | Implemented and tested | Advertised; failure/success and one-shot delayed reports, RET, xtext ENVID/ORCPT, null reverse paths and outbound requests are covered |
| Enhanced status codes (RFC 3463) | Implemented and tested | Consistent transactional replies; ENHANCEDSTATUSCODES is advertised |
| SMTP dot transparency | Implemented and tested | Outbound DATA normalizes line endings and dot-stuffs exactly once |

## Mail authentication

| Area | Status | Notes |
|---|---|---|
| SPF (RFC 7208) | Implemented, coverage incomplete | Null reverse-path HELO identity, duplicate records, include/redirect and error classes tested; exact MX/PTR subquery accounting remains |
| DKIM (RFC 6376/8463) | Implemented and tested | RSA/Ed25519 signing, DNS key parsing, expiration, required tags and multiple signatures; any passing valid signature can supply identity |
| DMARC | Implemented and tested | PSL organizational domains, strict/relaxed alignment, p/sp/pct and discovery/error classes |
| Authentication-Results (RFC 8601) | Implemented and tested | Correct header field, actual DKIM identity and injection-safe properties |
| ARC (RFC 8617) | Implemented, coverage incomplete | Cumulative multi-hop sealing/validation and cv semantics have deterministic tests; selected published draft-suite vectors pass, but live intermediaries and final-RFC vector breadth remain |

Ordinary locally originated mail is DKIM-signed but is not ARC-sealed. ARC is for
an intermediary that preserves prior authentication results while forwarding or
modifying a message. Previous unconditional ARC generation was removed because
it also embedded unsupported hard-coded pass results.

## Transport policy and DNS

| Area | Status | Notes |
|---|---|---|
| MTA-STS (RFC 8461) | Implemented and tested | TXT discovery required, policy parser validates required/duplicate fields, enforce/testing/none and one-label MX wildcard matching; a valid cached policy survives replacement-fetch failure |
| DANE/TLSA (RFC 6698/7672) | Implemented and tested | Requires DNSSEC-authenticated data; Usage 0/1/2/3, Selector 0/1 and Matching 0/1/2, malformed records and chain handling covered |
| DANE fallback | Explicit policy | `disabled`: PKIX only; `optional`: authenticated TLSA is checked and failure may fall back to PKIX; `required`: missing/invalid/mismatched authenticated TLSA fails delivery |
| DNSSEC trust | Resolver boundary documented | Built-in defaults use authenticated DNS-over-TLS resolvers; custom plain DNS is only appropriate on a trusted path |
| TLS-RPT (RFC 8460) | Partial | Failure persistence and report generation exist; success counts, complete policy grouping and event coverage remain |

DANE verification behavior and its trust boundary are documented in
[docs/dane_implementation.md](docs/dane_implementation.md).

## Message format and reporting

| Area | Status | Notes |
|---|---|---|
| RFC 5322/MIME parsing | Implemented, coverage incomplete | Charset conversion, RFC 2231 filenames, nested alternatives and related inline resources have deterministic tests; broad corpus testing remains |
| HTML email safety | Implemented and tested | Allowlist sanitizer plus sandboxed iframe isolation; remote resources still have privacy implications |
| MDN | Implemented, coverage incomplete | Manual/automatic paths exist |
| DSN generation | Implemented, coverage incomplete | RFC 3464 failure/success/delay reports and RET/ENVID/ORCPT behavior are tested; live interoperability remains |
| DMARC aggregate reporting | Implemented, coverage incomplete | Authentication identities, exact outcome grouping and external rua authorization are tested; live interoperability remains |

## Mailbox and clients

| Area | Status | Notes |
|---|---|---|
| Webmail | Implemented | Inbox/Sent/Spam/Drafts/Trash, compose, reply/forward, search and bulk actions |
| Drafts | Implemented and tested | Create, resume, update, autosave and remove after successful send |
| POP3 | Implemented and tested | Optional implicit TLS on 995; USER/PASS, CAPA, STAT, LIST, UIDL, RETR, TOP, DELE, RSET, NOOP, QUIT; Inbox only |
| SMTP submission | Implemented and tested at component level | Optional port 587, mandatory STARTTLS before AUTH PLAIN/LOGIN, sender identity restriction, Bcc removal and queue integration |
| IMAP | Implemented, live compatibility pending | Durable UIDs/mod-sequences, folders, flags, MIME sections, IDLE, UIDPLUS, MOVE, CONDSTORE and QRESYNC; disabled by default |
| Autoconfiguration | Implemented, live compatibility pending | Thunderbird and Outlook XML endpoints advertise only enabled, TLS-backed services |

POP3 and submission are gated by `mail_clients.enabled`, which defaults to
`false`. TLS is mandatory, authentication is rate limited per IP, and POP3
maildrops are locked per account. Live Thunderbird/Outlook/Apple Mail matrices
remain to be run.

## Web and operational security

- Bcrypt account passwords; HTTP-only session cookies; Secure cookies with
  direct HTTPS or configured external HTTPS termination.
- CSRF checks and account-scoped mailbox operations.
- Attachment download authorization is joined through the owning account;
  attachment identifiers alone never authorize file access.
- Trusted proxy CIDRs are required before forwarded client-address headers are
  honored.
- Web and SMTP rate limits plus mail-client authentication throttling.
- `/healthz` and `/readyz` endpoints.
- SQLite/MySQL additive schema synchronization and migration tracking.

Operational monitoring, encrypted off-host backup, and restore drills are
operator responsibilities. The server supports scheduled local verified backups,
but operators must copy archives to encrypted off-host storage and test restores.

## Required remaining verification

1. Broader final-RFC ARC vectors and live intermediary tests. Selected vectors
   from the archived ValiMail draft suite are covered locally.
2. Live DSN and SMTP interoperability against common providers.
3. Live POP3 and submission matrices against common clients.
4. Browser interaction and accessibility automation.

Do not replace these items with blanket “fully RFC compliant” claims until the
corresponding tests and interoperability evidence exist.
