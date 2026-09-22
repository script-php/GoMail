# Feature status

This file previously contained a line-by-line feature report that had drifted
from the code and labeled partially tested protocols “production ready.” The
maintained current status is now split across:

- [README.md](README.md) — supported product features and boundaries.
- [STANDARDS_AUDIT.md](STANDARDS_AUDIT.md) — protocol implementation and known gaps.
- [docs/config.md](docs/config.md) — configuration and defaults.
- [docs/architecture.md](docs/architecture.md) — package and data-flow design.
- [TODO.md](TODO.md) — remaining engineering work.

Notable additions as of 2026-09-22 are draft autosave/resume, allowlist HTML
sanitization with iframe isolation, trusted-proxy handling, health/readiness
endpoints, audited DANE/TLSA semantics, stricter SPF/DKIM/DMARC handling, corrected
SMTP DATA/SMTPUTF8/8BITMIME behavior, and opt-in POP3 plus authenticated SMTP
submission.
