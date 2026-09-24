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
- Move TLS-RPT generation to daily UTC windows, add HTTPS `rua` transport and
  explicit retry state, independently of the DMARC weekly scheduler.
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

## Completed webmail follow-up (2026-09-23)

- Users can permanently delete account-owned messages from Trash, individually
  or in bulk. Database rows and attachment records are removed atomically, and
  contained attachment files are cleaned up after commit.
- Saved drafts have an explicit, account-scoped permanent delete action.
- The user Settings page supports display-name updates and authenticated
  password changes without exposing administrative account controls.

## Completed protocol follow-up (2026-09-23)

- SPF now enforces the global ten DNS-term limit without charging MX/PTR
  expansion queries as extra terms, caps MX/PTR expansion as RFC 7208 requires,
  applies the two-void-lookup ceiling, and propagates mechanism DNS errors with
  the RFC-specific PTR exceptions.
- SPF validates the complete record before evaluation, rejects malformed dual
  CIDR lengths and duplicate known modifiers, ignores repeated unknown
  modifiers, treats mechanism/modifier names case-insensitively, and makes
  `exists` depend on an IPv4 A result.
- TLS-RPT stores successful and failed TLS policy evaluations, preserves STS,
  TLSA and no-policy descriptions, groups summaries/failure details by applied
  policy, and emits RFC 8460 multipart report messages with required headers.

## Optional future features

- Vacation responses, Sieve-style filtering and mailing lists.
- Two-factor web authentication and account recovery.
- BIMI, CalDAV/CardDAV and PGP/S/MIME integrations.
