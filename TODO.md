# Remaining work

## Completed security follow-up (2026-09-23)

- Attachment downloads now join through the owning message/account; guessed IDs
  return 404 across accounts. Stored paths are confined to `attachments_path`,
  and download headers use safe media-type formatting.
- Audited the remaining user-facing ID routes for account scoping.
- Corrected `strip_originating_ip`: enabled now removes the address from both
  Received and X-Originating-IP headers.
- Removed the unused outbound ARC helper that hard-coded authentication passes.

## Protocol and interoperability

- Complete ARC multi-hop sealing and validation with published vectors and live
  intermediary tests. Do not enable ARC on ordinary originated mail.
- Complete SPF MX/PTR DNS subquery/error accounting.
- Add complete TLS-RPT success/failure event storage and policy grouping.
- Expand DMARC aggregate `auth_results` data and external destination tests.
- Complete DSN syntax/interoperability and use enhanced status codes consistently
  before advertising `ENHANCEDSTATUSCODES`.
- Add MIME charset conversion, RFC 2231 filename handling, and multipart
  alternative/related fixtures.
- Run live SMTP interoperability against major providers.

## Mail clients

- Run Thunderbird, Outlook and Apple Mail interoperability matrices for POP3
  and submission.
- Implement IMAP only as a complete mailbox synchronization project: stable
  UID/UIDVALIDITY, folders, flags, SEARCH/FETCH/STORE, IDLE, concurrent updates
  and expunge semantics.
- Add standard client autoconfiguration/autodiscovery only after endpoints and
  certificate deployment are stable.

## Product and operations

- Browser-level interaction and accessibility automation.
- Complete mailbox quota enforcement.
- Structured metrics/alerts for queues, SMTP results, auth failures, reports,
  DNSSEC/TLSA and certificate expiry.
- Automated, documented backup tooling and repeated restore tests.
- Broader parser, reporting and web-handler integration coverage.
- Review logging consistency and remove remaining direct `log`/`fmt` output.
- Cursor-based mailbox pagination for large installations.

## Optional future features

- Vacation responses, Sieve-style filtering and mailing lists.
- Two-factor web authentication and account recovery.
- BIMI, CalDAV/CardDAV and PGP/S/MIME integrations.
