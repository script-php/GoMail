# Implemented improvements and remaining work

## Implemented

- Account-scoped mailbox search, signed keyset pagination for mailbox/folder/
  search views, bulk read/unread/move/trash/restore and ownership validation.
- Transactional Sent-copy and recipient-queue insertion.
- Draft create/resume/update, explicit save, autosave and deletion after send.
- Allowlist HTML sanitizer and sandboxed iframe rendering.
- Trusted-proxy CIDRs, external HTTPS awareness, secure cookies and correct
  client-IP rate-limit identity.
- Liveness/readiness endpoints and documented backup/restore expectations.
- Stricter SMTP command parameters, STARTTLS reset, outbound dot transparency,
  SMTPUTF8 and 8BITMIME negotiation.
- Multi-signature DKIM identity handling, SPF/HELO behavior, PSL-aware DMARC and
  safer Authentication-Results construction.
- DNSSEC-authenticated DANE/TLSA matching for every usage/selector/matching type.
- MTA-STS TXT discovery and stricter policy parsing/matching.
- Removal of unconditional ARC from ordinary outbound mail.
- Optional POP3-over-TLS and authenticated SMTP submission, disabled by default.
- Account-scoped attachment downloads with path containment and safe download
  header formatting; cross-account attachment IDs return 404.
- Correct originating-IP privacy behavior for both compose and forward paths.
- RFC 7208 SPF DNS-term/void limits, MX/PTR expansion accounting, DNS error
  propagation, complete-record syntax validation, modifier handling and strict
  macro grammar/transformer/escaping coverage with validated `%{p}` expansion.
- TLS-RPT success/failure event storage, STS/TLSA/no-policy grouping, aggregated
  diagnostics and RFC 8460 email report formatting.
- Permanent Trash deletion with attachment cleanup, explicit draft deletion and
  self-service profile/password settings.
- Cumulative ARC multi-hop signing and cryptographic validation, including
  duplicate/incomplete/oversized-chain rejection and `cv=fail` handling.
- Receiver-side DSN success reports and one-shot queue delay reports, with null
  reverse paths, loop prevention and retained incoming non-failure reports.
- MIME-aware DSN parsing with folded and multi-recipient status blocks, plus
  case-insensitive MIME types, bounded nesting and HTML-only text fallback.
- Transactional mailbox quotas with existing-data backfill, atomic
  multi-recipient delivery, draft size-delta accounting, permanent-deletion
  reclamation and usage displays for users and administrators.
- Versioned, checksummed offline backup verification and guarded restore tooling
  with consistent SQLite snapshots, MySQL dump support and instance locking.
- Admin-controlled manual and scheduled online verified backups with bounded
  retention and no web download of secret-bearing archives.
- Isolated Playwright interaction tests for Chromium, Firefox and WebKit,
  including keyboard/mobile flows and axe-core WCAG A/AA checks.
- Atomic account/default-folder provisioning and admin account/password edits,
  with attachment-file cleanup after committed account or domain deletion.
- Native fuzz entry points for MIME messages, DSNs, ESMTP parameters and SPF
  macro grammar.
- Fail-closed local-recipient routing, required Inbox/Sent folder invariants,
  pre-queue signed-message validation and stricter administrator account and
  backup input validation.

## Remaining

- Continue independent final-RFC ARC vectors beyond the static one-, two-, and
  three-hop dkimpy-signed messages; run live intermediary interoperability tests.
- Run live IMAP/POP3/submission client matrices and extended IMAP load/failure
  testing.
- Run the opt-in isolated MySQL backup/restore test with a suitably privileged
  test account, then complete a separately observed restore drill.

The authoritative list is [../TODO.md](../TODO.md); protocol detail is in
[../STANDARDS_AUDIT.md](../STANDARDS_AUDIT.md).
