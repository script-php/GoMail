# Deployment guide

This guide describes a conservative single-instance deployment. Read
[config.md](config.md), [dns_records.md](dns_records.md), and
[../STANDARDS_AUDIT.md](../STANDARDS_AUDIT.md) first.

## Requirements

- Linux host with a static public IP and control of forward/PTR DNS.
- The Go version declared in `go.mod` when building from source.
- Port 25 inbound and outbound for Internet SMTP.
- Port 80 for ACME HTTP challenges and 443 for webmail when using direct HTTPS.
- Optional 995 (POP3 TLS) and 587 (submission STARTTLS) only when
  `mail_clients.enabled` is true.
- Persistent storage for the database, attachments and ACME cache.

Many residential/cloud providers block port 25. Confirm this before deployment.

## Build

```bash
go build -o gomail .
./gomail -hash-password 'use-a-strong-password'
```

GoMail does not implement `-setup` or `-version` command-line flags. DKIM keys are
generated through the admin domain UI after the initial account is bootstrapped.

## Configuration

Create `config.json` from [config.md](config.md). At minimum set:

- `server.hostname` to the public mail hostname.
- `tls.mode` and ACME or manual certificate settings.
- persistent database/attachment paths.
- long random web secrets.
- `web.bootstrap_admin` email and generated bcrypt hash.
- queue/retry and SMTP limits appropriate to the host.

Keep mail-client access off until public SMTP/webmail are stable:

```json
"mail_clients": {
  "enabled": false,
  "pop3": { "enabled": true, "listen_addr": ":995" },
  "submission": { "enabled": true, "listen_addr": ":587" }
}
```

When TLS and firewall rules are ready, changing only the master flag enables the
two subservices unless either child `enabled` value is false.

## DNS rollout

1. Publish A/AAAA for the mail hostname and set matching PTR.
2. Publish MX for every managed domain.
3. Start with a narrow, accurate SPF record.
4. Generate DKIM in the admin UI and publish the exact selector/key shown.
5. Start DMARC with `p=none` and monitored aggregate reports.
6. Add MTA-STS/TLS-RPT and DNSSEC/TLSA only after base mail flow is stable.

Never enable DANE `required` before confirming the DNSSEC chain, resolver AD
response, TLSA owner name and active certificate match.

## Service installation

The binary can install its current directory/configuration as a systemd service:

```bash
sudo ./gomail -config /opt/gomail/config.json -register
```

Equivalent positional syntax is `sudo ./gomail register`. Review the generated
unit, user, working directory and writable paths before relying on it.

For a manual unit, run one GoMail process per database. Grant only the bind
capability needed for privileged ports and write access only to data/certificate
paths. Do not place secrets in command arguments or world-readable files.

## Firewall

Typical direct deployment:

```bash
sudo ufw allow 25/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

Only after enabling mail-client services:

```bash
sudo ufw allow 587/tcp
sudo ufw allow 995/tcp
```

Port 993 is not needed because IMAP is not implemented. Port 587 is authenticated
submission, not the public server-to-server SMTP listener.

## Reverse proxy

If a proxy terminates HTTPS, set `web.enable_tls: false`,
`web.external_https: true`, and list only the proxy IP/CIDR under
`web.trusted_proxies`. Never trust `0.0.0.0/0`; forwarded headers determine both
rate-limit identity and security context.

SMTP, POP3 and submission are raw TCP protocols and are not handled by an HTTP
reverse proxy unless it explicitly supports TCP forwarding with correct TLS
semantics.

## Initial verification

```bash
curl -fsS https://mail.example.com/healthz
curl -fsS https://mail.example.com/readyz
openssl s_client -starttls smtp -connect mail.example.com:25 -servername mail.example.com
```

When mail clients are enabled:

```bash
openssl s_client -connect mail.example.com:995 -servername mail.example.com
openssl s_client -starttls smtp -connect mail.example.com:587 -servername mail.example.com
```

Test local delivery, one external delivery, inbound delivery, a temporary remote
failure/retry, and a permanent failure. Inspect SPF/DKIM/DMARC results and verify
the active DKIM DNS key matches the private key stored for the domain.

## Monitoring

Alert on:

- process/readiness failure;
- queue age, pending/failed growth and repeated 4xx/5xx changes;
- SMTP, web and optional client-port reachability;
- disk/database capacity and attachment filesystem errors;
- TLS certificate and DNSSEC signature expiry;
- repeated MTA-STS, DNSSEC/TLSA or DKIM signing failures;
- authentication-rate-limit activity and abnormal login failures;
- report scheduler errors.

Health endpoints do not replace a functional send/receive probe.

## Backup and restore

Back up the database and attachment directory from the same recovery point.

- SQLite: pause ingestion or use the SQLite online backup command/snapshot, then
  capture attachments consistently. Do not blindly copy a live WAL database
  without its WAL/SHM state or a database-aware backup.
- MySQL: use a consistent dump/snapshot and capture attachments corresponding to
  that point.
- Also preserve configuration and ACME state, protect private keys, encrypt
  backups and keep at least one off-host copy.

Restore into an isolated host and verify schema startup, account/message counts,
attachment hashes, login, draft access, inbound SMTP, local delivery, queued
outbound delivery and—if enabled—POP3/submission login. A backup is not verified
until a restore drill succeeds.

## Upgrade and rollback

1. Read the diff and updated schema/migration notes.
2. Take and verify a consistent backup.
3. Stop the service, replace the binary, and start once against the database.
4. Check logs, `/readyz`, migrations and representative mail flows.
5. Keep the previous binary and backup. Schema synchronization is additive, but
   a binary rollback may still be incompatible with newly written data.

## Scale boundary

Current queue claiming is coordinated inside one process. Do not run multiple
GoMail application instances against one database. Large mailboxes still use
offset pagination, and full high-volume/provider-scale operation has not been
validated.
