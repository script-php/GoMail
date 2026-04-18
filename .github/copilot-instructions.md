---
description: GoMail workspace instructions for AI agents. Use when working on the GoMail mail server project—building features, fixing issues, refactoring, or extending functionality.
---

# GoMail Workspace Instructions

**GoMail** is a self-hosted mail server written in Go. It replaces Postfix/Exim (MTA) and Dovecot (MDA) as a single binary with a web UI, supporting multi-domain SMTP receive/send, email authentication (SPF/DKIM/DMARC), TLS security, and SQLite storage.

See [README.md](../README.md) for feature overview and [docs/architecture.md](../docs/architecture.md) for design details.

## Quick Start

### Build & Run

```bash
# Build the binary
go build -o gomail .

# Run with default config
./gomail -config config.json

# Run with local dev config (plaintext SMTP, no TLS)
./gomail -config config.dev.json

# Hash a password for bootstrap admin
./gomail -hash-password "my_password"
```

### Test

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests for a specific package
go test ./smtp
```

### Local Development

- **Web UI**: `http://localhost:8080` (default: `admin@localhost` / `admin`)
- **SMTP Server**: `localhost:2525` (plaintext for testing)
- **Config**: [config.dev.json](../config.dev.json) — uses `tls.mode: "none"`
- **Database**: SQLite auto-initialized on first run at path in config

## Project Structure

### Core Packages

| Package | Purpose |
|---------|---------|
| `main.go` | Entry point, component wiring, startup lifecycle |
| `config/` | Configuration parsing/validation (JSON-based) |
| `smtp/` | SMTP protocol (inbound server, outbound client, session state machine) |
| `store/` | SQLite persistence layer, schema, migrations, CRUD ops |
| `parser/` | RFC 5322 email parsing, MIME handling, attachments |
| `auth/` | Email authentication (SPF, DKIM, DMARC, ARC), header generation |
| `delivery/` | Outbound message queuing, DKIM signing, retry logic |
| `web/` | HTTP server, routes, middleware |
| `web/handlers/` | Handler functions (admin, auth, compose, inbox, message) |
| `web/templates/` | HTML templates + CSS/JS |
| `tls/` | TLS certificates, ACME (Let's Encrypt), DANE |
| `dns/` | MX lookups, reverse DNS, TTL caching |
| `security/` | Session tokens, CSRF protection, HTTP security headers |
| `reporting/` | DMARC feedback, DSN, TLS-RPT, scheduling |

### Key Entry Points for Understanding Email Flow

1. **Inbound email**: `smtp/inbound.go` → `parser/message.go` → `store/messages.go` → web handlers
2. **Outbound email**: `web/handlers/compose.go` → `delivery/queue.go` → `smtp/outbound.go` → MX lookup
3. **Authentication**: `auth/` (SPF/DKIM/DMARC verification) → `auth/results.go` (header generation)

## Coding Conventions

### Logging

Use the `[package_name]` prefix format for all logs:

```go
log.Printf("[smtp] Received MAIL FROM: %s", mailFrom)
log.Printf("[delivery] Retry worker processing queue")
log.Printf("[db] Updating message flags")
```

This makes debugging easier and identifies the source package at a glance.

### Error Handling

Follow standard Go patterns:
- Always check errors explicitly: `if err != nil { ... }`
- Return errors at call sites; don't hide them
- Use descriptive error messages with context
- No custom error types (keep it simple)

### Configuration

- Nested JSON structs in `config/config.go` map directly to `config.json`
- Separate dev config: [config.dev.json](../config.dev.json) for local testing
- Access config via passed `*config.Config` parameter, not globals

### Package Organization

- One logical feature per package (e.g., `auth/` handles all authentication)
- Public functions/types exported (Capital), private unexported (lowercase)
- Database models live in `store/` with CRUD methods
- HTTP handlers organized by feature in `web/handlers/`

## Development Tasks

### Adding a New Feature

1. **Identify host package**: Features belong in domain-specific packages (e.g., new report type in `reporting/`, new SMTP command in `smtp/`)
2. **Add database schema**: Update [store/schema.sql](../store/schema.sql) and create migration in `store/db.go`
3. **Implement business logic**: Write types and functions in appropriate package
4. **Wire into main.go**: Register handlers, start goroutines as needed
5. **Add tests**: Create `*_test.go` files in the same package
6. **Update docs**: Add to [docs/architecture.md](../docs/architecture.md) if it's significant

### Adding a New Email Handler/Panel

1. Create handler in `web/handlers/` (e.g., `web/handlers/myfeature.go`)
2. Create template in `web/templates/` (HTML file)
3. Register route in `web/server.go`
4. Access logged-in user via session token in middleware
5. Follow existing patterns in [web/handlers/inbox.go](../web/handlers/inbox.go) or [web/handlers/admin.go](../web/handlers/admin.go)

### Updating Email Authentication

- SPF: [auth/spf.go](../auth/spf.go)
- DKIM signing/verification: [auth/dkim.go](../auth/dkim.go)
- DMARC policy evaluation: [auth/dmarc.go](../auth/dmarc.go)
- Result headers: [auth/results.go](../auth/results.go)

See [standards.md](../standards.md) for current RFC compliance targets.

### Database Operations

1. Define schema changes in [store/schema.sql](../store/schema.sql)
2. Create a migration function: `func MigrateXxx(db *sql.DB) error`
3. Register in `RegisteredMigrations()` in [store/db.go](../store/db.go)
4. Add CRUD methods to `*DB` type in `store/messages.go` or `store/models.go`

## Standards & Best Practices

- **SMTP**: See [standards.md](../standards.md) for RFC compliance, authentication headers, and deliverability
- **Security**: TLS support via Let's Encrypt ([tls/autocert.go](../tls/autocert.go)), DANE verification, security headers
- **Testing**: Use `config.dev.json` for local tests; run `go test ./...` before pushing
- **Logging**: Always use `[package_name]` prefix; grep logs for debugging

## Documentation

- [README.md](../README.md) — Features and quick start
- [docs/architecture.md](../docs/architecture.md) — Design, package breakdown, data flow
- [docs/config.md](../docs/config.md) — Configuration reference
- [docs/deployment.md](../docs/deployment.md) — Production deployment
- [docs/dns_records.md](../docs/dns_records.md) — DNS requirement reference
- [standards.md](../standards.md) — SMTP/email standards compliance
- [TODO.md](../TODO.md) — Planned features and known gaps

## Tips for Working in GoMail

- **Understand the data flow**: Trace an inbound email from SMTP server → parser → store → web. Trace an outbound email from compose handler → queue → retry worker → SMTP client.
- **Use `config.dev.json` for testing**: Disables TLS, sets up localhost endpoints, uses example DNS
- **Check existing handlers/packages first**: Similar features likely exist; follow the pattern
- **Database schema is canonical**: [store/schema.sql](../store/schema.sql) defines the data model
- **Test locally before production**: The binary embeds SQLite, so build once and test thoroughly

## Common Issues

| Issue | Solution |
|-------|----------|
| Build fails | Ensure Go 1.21+: `go version`. Run `go mod tidy` |
| TLS certificate errors | For dev, use `config.dev.json` with `tls.mode: "none"` |
| SMTP not receiving mail | Verify MX records point to your server; check inbound/outbound on public internet, not localhost |
| DKIM signature fails | Ensure DKIM key is loaded for domain; check `auth/dkim.go` signature generation |
| SQLite locked errors | Ensure only one running instance; check that database file isn't corrupted |
| Web login fails | Check bootstrap admin credentials in config; use `-hash-password` to update |

