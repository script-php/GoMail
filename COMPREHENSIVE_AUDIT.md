# Comprehensive audit index

The former version of this document mixed implemented features, aspirations and
unsupported claims of full RFC compliance. It is retained as an index so old
links continue to work, while current facts live in focused documents:

- [STANDARDS_AUDIT.md](STANDARDS_AUDIT.md) — security/protocol status and gaps.
- [README.md](README.md) — current supported feature set.
- [docs/dane_implementation.md](docs/dane_implementation.md) — DNSSEC/TLSA behavior.
- [docs/database.md](docs/database.md) — SQLite/MySQL schema and migration behavior.
- [docs/config.md](docs/config.md) — all supported settings.
- [docs/deployment.md](docs/deployment.md) — deployment and operations.
- [TODO.md](TODO.md) — work that must not be described as complete.

The current project does not claim universal production readiness or complete
conformance with every referenced RFC. Repository tests, builds and vet checks
are the evidence baseline; live interoperability and independent security review
remain separate requirements.
