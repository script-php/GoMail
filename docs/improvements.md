# Implemented improvements and remaining work

## Implemented

- Account-scoped mailbox search, pagination, bulk read/unread/move/trash/restore
  and ownership validation.
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

## Remaining

- Complete ARC multi-hop interoperability.
- Complete TLS-RPT and DMARC aggregate event/report fields.
- Exact SPF MX/PTR DNS accounting and broader MIME/DSN fixtures.
- Live POP3/submission client matrices and a complete IMAP design.
- Browser-level interaction and accessibility automation.
- Complete quota enforcement, metrics/alerting, backup tooling and restore drills.

The authoritative list is [../TODO.md](../TODO.md); protocol detail is in
[../STANDARDS_AUDIT.md](../STANDARDS_AUDIT.md).
