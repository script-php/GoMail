# GoMail standards and interoperability status

**Updated:** 2026-09-22
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
| DSN extension (RFC 3461) | Partial | Parameters and failure-report path exist; exact syntax/provider interop remains |
| Enhanced status codes (RFC 3463) | Partial, not advertised | Responses are not consistently enhanced-status formatted |
| SMTP dot transparency | Implemented and tested | Outbound DATA normalizes line endings and dot-stuffs exactly once |

## Mail authentication

| Area | Status | Notes |
|---|---|---|
| SPF (RFC 7208) | Implemented, coverage incomplete | Null reverse-path HELO identity, duplicate records, include/redirect and error classes tested; exact MX/PTR subquery accounting remains |
| DKIM (RFC 6376/8463) | Implemented and tested | RSA/Ed25519 signing, DNS key parsing, expiration, required tags and multiple signatures; any passing valid signature can supply identity |
| DMARC | Implemented and tested | PSL organizational domains, strict/relaxed alignment, p/sp/pct and discovery/error classes |
| Authentication-Results (RFC 8601) | Implemented and tested | Correct header field, actual DKIM identity and injection-safe properties |
| ARC (RFC 8617) | Partial | Structural and cryptographic code exists, but full multi-hop sealing/validation and external vectors are incomplete |

Ordinary locally originated mail is DKIM-signed but is not ARC-sealed. ARC is for
an intermediary that preserves prior authentication results while forwarding or
modifying a message. Previous unconditional ARC generation was removed because
it also embedded unsupported hard-coded pass results.

## Transport policy and DNS

| Area | Status | Notes |
|---|---|---|
| MTA-STS (RFC 8461) | Implemented and tested | TXT discovery required, policy parser validates required/duplicate fields, enforce/testing/none and one-label MX wildcard matching |
| DANE/TLSA (RFC 6698/7672) | Implemented and tested | Requires DNSSEC-authenticated data; Usage 0/1/2/3, Selector 0/1 and Matching 0/1/2, malformed records and chain handling covered |
| DANE fallback | Explicit policy | `disabled`: PKIX only; `optional`: authenticated TLSA is checked and failure may fall back to PKIX; `required`: missing/invalid/mismatched authenticated TLSA fails delivery |
| DNSSEC trust | Resolver boundary documented | Built-in defaults use authenticated DNS-over-TLS resolvers; custom plain DNS is only appropriate on a trusted path |
| TLS-RPT (RFC 8460) | Partial | Failure persistence and report generation exist; success counts, complete policy grouping and event coverage remain |

DANE verification behavior and its trust boundary are documented in
[docs/dane_implementation.md](docs/dane_implementation.md).

## Message format and reporting

| Area | Status | Notes |
|---|---|---|
| RFC 5322/MIME parsing | Partial | Common multipart/text/HTML/attachments work; charset conversion, RFC 2231 filenames and multipart related/alternative edge cases need tests |
| HTML email safety | Implemented and tested | Allowlist sanitizer plus sandboxed iframe isolation; remote resources still have privacy implications |
| MDN | Implemented, coverage incomplete | Manual/automatic paths exist |
| DSN generation | Partial | Failure generation exists; external interoperability coverage remains |
| DMARC aggregate reporting | Partial | Policy fields and external rua authorization are handled; complete auth_results population and interoperability tests remain |

## Mailbox and clients

| Area | Status | Notes |
|---|---|---|
| Webmail | Implemented | Inbox/Sent/Spam/Drafts/Trash, compose, reply/forward, search and bulk actions |
| Drafts | Implemented and tested | Create, resume, update, autosave and remove after successful send |
| POP3 | Implemented and tested | Optional implicit TLS on 995; USER/PASS, CAPA, STAT, LIST, UIDL, RETR, TOP, DELE, RSET, NOOP, QUIT; Inbox only |
| SMTP submission | Implemented and tested at component level | Optional port 587, mandatory STARTTLS before AUTH PLAIN/LOGIN, sender identity restriction, Bcc removal and queue integration |
| IMAP | Not implemented | No folder/flag/UID synchronization protocol |
| Autoconfiguration | Not implemented | Clients must be configured manually |

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
operator responsibilities. Repository documentation describes the procedure;
the server does not contain a scheduler that performs backups automatically.

## Required remaining verification

1. Full ARC multi-hop construction and external RFC vectors.
2. Exact SPF DNS term/subquery accounting, especially MX and PTR error cases.
3. TLS-RPT success/failure event model and policy grouping.
4. MIME charset, RFC 2231 and multipart semantic fixtures.
5. DSN/enhanced-status interoperability.
6. DMARC aggregate auth_results completeness and external-reporting tests.
7. Live SMTP, POP3 and submission matrices against common servers and clients.
8. Browser interaction and accessibility automation.

Do not replace these items with blanket “fully RFC compliant” claims until the
corresponding tests and interoperability evidence exist.
