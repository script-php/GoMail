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

- `server.hostname` to a public, fully qualified mail hostname (for example,
  `mail.example.com`). GoMail validates its SMTP wire syntax at startup;
  `localhost` is accepted only as a local-development exception. DNS and PTR
  correctness still require deployment checks.
- `tls.mode` and ACME or manual certificate settings.
- persistent database/attachment paths.
- long random web secrets.
- `web.bootstrap_admin` email and generated bcrypt hash.
- queue/retry and SMTP limits appropriate to the host.

Keep mail-client access off until public SMTP/webmail are stable:

```json
"mail_clients": {
  "enabled": false,
  "imap": { "enabled": false, "listen_addr": ":993" },
  "pop3": { "enabled": true, "listen_addr": ":995" },
  "submission": { "enabled": true, "listen_addr": ":587" }
}
```

When TLS and firewall rules are ready, changing the master flag enables POP3
and submission unless either child switch is false. IMAP always requires its
own explicit switch and should remain off until its compatibility testing is
complete.

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
# Experimental IMAP only when explicitly enabled:
sudo ufw allow 993/tcp
```

Port 993 is used only by explicitly enabled experimental IMAP. Port 587 is
authenticated submission, not the public server-to-server SMTP listener.

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
curl -fsS 'https://mail.example.com/mail/config-v1.1.xml?emailaddress=user@example.com'
curl -fsS -X POST -H 'Content-Type: application/xml' \
  --data '<Autodiscover><Request><EMailAddress>user@example.com</EMailAddress></Request></Autodiscover>' \
  https://mail.example.com/autodiscover/autodiscover.xml
```

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

For MySQL, an opt-in isolated round-trip test is available:

```sh
GOMAIL_TEST_MYSQL_CONFIG=/absolute/path/to/config.local.json \
  go test ./backup -run TestMySQLBackupRestoreIsolatedRoundTrip -count=1
```

It creates two uniquely named disposable databases, restores into the second,
compares restored data, then drops both. Run it only with a test MySQL account
that can create and drop those databases; the configured production database is
not used as either target. Normal application accounts usually lack those
privileges. This does not replace a separately observed operator restore drill.

If the test account has rights only to an existing, empty `gomailtest` database,
use the fixed-database mode instead:

```sh
GOMAIL_TEST_MYSQL_CONFIG=/absolute/path/to/config.local.json \
GOMAIL_TEST_MYSQL_FIXED_DB=gomailtest \
GOMAIL_TEST_MYSQL_USER=gomailtest \
GOMAIL_TEST_MYSQL_PASSWORD='your-test-password' \
  go test ./backup -run TestMySQLBackupRestoreIsolatedRoundTrip -count=1
```

The test refuses a nonempty database or the database named in the supplied
config, restores into that same dedicated test database, then removes its test
tables. It also checks that a change made after backup disappears on restore.
The MySQL storage integration test accepts the same dedicated database through
`GOMAIL_TEST_MYSQL_ADDR`, `GOMAIL_TEST_MYSQL_DATABASE`, and the user/password
variables; it leaves the schema in place, so reset the test database before
rerunning the backup/restore test.

GoMail provides a versioned `tar.gz` backup containing a consistent SQLite
snapshot or MySQL dump, attachments, configuration, ACME state and manual TLS
key/certificate files. Its manifest records GoMail/format versions, database
row counts, sizes and SHA-256 hashes.
Creation checks that attachment references in the captured SQLite snapshot
or current MySQL database point to regular files of the recorded size before
publishing the archive. This catches already-broken source data early.
Verification rejects missing, negative, or unknown table counts before a
restore begins. A completed archive is synced to disk along with its directory
entry before backup success is reported. Restore rechecks each extracted file's
size and SHA-256 hash against the verified manifest, so a changed archive is
rejected before the database or live files are touched.

The running server and backup/restore commands use the same exclusive instance
lock. Stop GoMail before creating or restoring an archive; the command refuses
to proceed if another GoMail process owns the instance. For MySQL the lock now
lives beside, not inside, the attachment directory so a restore cannot replace
the locked inode. It also honors the previous in-tree lock during upgrades.

```bash
sudo systemctl stop gomail
./gomail -config ./config.local.json -backup /secure/gomail-2026-10-14.tar.gz
./gomail -verify-backup /secure/gomail-2026-10-14.tar.gz
sudo systemctl start gomail
```

For MySQL, `mysqldump` must be installed. GoMail invokes it with
`--single-transaction`; the configured password is supplied through the child
process environment rather than command arguments. When `store.mysql.tls` is
`true`, both `mysqldump` and `mysql` are invoked with
`--ssl-mode=VERIFY_IDENTITY`, matching the application's verified-TLS policy.
Install client utilities that support that option; an unsupported client
fails the operation rather than silently using opportunistic TLS.

Restore is deliberately destructive and requires both a stopped instance and
explicit confirmation:

```bash
sudo systemctl stop gomail
./gomail -config ./config.local.json \
  -restore-backup /secure/gomail-2026-10-14.tar.gz -force-restore
sudo systemctl start gomail
```

Restore verifies every archive hash, requires the configuration and matching
database snapshot, and rejects duplicate archive paths before replacing
configured state. SQLite restores stage all filesystem replacements before
removing the old WAL/SHM sidecars. SQLite and both in-place and staged MySQL restores now
check all manifest table counts and every attachment reference against the staged
attachment tree before activating it. An archive with no attachments restores
an empty attachment directory. Restore refuses filesystem-root,
current-directory, or overlapping destinations (for example, a configuration
file inside the attachment directory). MySQL restore requires the `mysql`
command. Before either SQLite or MySQL restore mutates live state, GoMail creates and verifies a
`gomail-pre-restore-*.tar.gz` safety archive next to the configuration file; if
that fails, restore does not begin. Keep that archive until the restored server
has been checked. For MySQL, attachment and ACME trees are also fully staged
on their destination filesystems before the dump import starts. The restored
configuration and any manual TLS certificate/key are likewise staged as sibling
files before import; staging failure leaves the live database untouched. MySQL
dump imports and the later filesystem swaps are not atomic together: if restore
fails partway through, stop the server and recover
from the safety archive before accepting mail. Both SQLite and MySQL restores write a
`config.local.json.restore-incomplete` marker beside the chosen config before
their first state change. Normal startup refuses to serve while it exists. The
marker contains the requested archive path and the safety-archive
path; remove it only after checking that the
database, attachments, TLS material and config form one consistent generation.
An interrupted restore cannot be retried until that reconciliation is done.
For MySQL, the restored
configuration preserves the selected destination database connection,
attachment path, TLS file/directory paths, and DKIM key directory instead of
reinstalling source-host locations from the archive. A TLS-mode mismatch is
rejected before database import; review all other restored settings before
restarting the service.
The staged-database and crash-recovery design is described in
`docs/mysql_staged_restore.md`. An opt-in staged import is available, but
automatic crash recovery is not implemented yet. To use it, pre-provision a
distinct *empty* MySQL database and grant the configured GoMail database user
access to it. Stop GoMail, then use:

```bash
./gomail -config ./config.local.json \
  -restore-backup /secure/gomail-2026-10-14.tar.gz \
  -restore-stage-db gomail_restore_stage -force-restore
```

The restore checks the staging database is empty, imports and verifies manifest
table counts and every attachment file reference there, then switches the
restored config to that database. Attachment references must be relative
filenames resolving to regular files in the restored tree with matching sizes;
legacy absolute paths are rejected before activation. It
retains the previous database, attachment and ACME directory generations, and
safety archive. The previous directory paths are recorded in the restore marker
and printed on success; keep them until the restored instance has been checked.
The marker also records the last completed phase, but a crash can happen
between a file switch and its phase update. It is not proof by itself of which
generation is active.
The staged database must not
be used by another service or process. If the restore fails after the file
switch begins, the incomplete marker blocks startup; an operator must still
reconcile the files and database before clearing it. Do not drop either
database until the restored server and attachment references are verified.

Attachment and certificate directory restores are copied into a sibling staging
directory and swapped only after the full tree succeeds. A staging failure
therefore leaves the live tree untouched.

Archives contain passwords, private keys and message data. GoMail restricts the
archive to mode `0600`, but it does not manage encryption or retention. Encrypt
the archive, keep at least one off-host copy and protect its encryption key
separately. The backup command refuses to overwrite an existing archive.

Administrators can also open **Admin → Backups** to create an online verified
backup or configure an interval and retention count. Online archives use a
database snapshot/dump and immutable attachment files, then verify every hash;
changes to a file during capture fail the backup. MySQL's live dump and
attachment-tree capture are not one atomic snapshot: concurrent same-count
database changes or attachment races still need a quiet period and an isolated
restore drill. The page writes archives only to the configured server directory and
never offers secret-bearing archives as browser downloads. Automatic retention
deletes only scheduler-generated timestamped archives (`gomail-YYYYMMDDTHHMMSS[.nanoseconds]Z.tar.gz`),
not `gomail-pre-restore-*` safety archives or other manually named files.

The admin scheduler is convenient, but the stopped-service CLI procedure above
remains the strongest recovery-point boundary. Use the CLI for upgrades and
before high-risk maintenance.

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

## Admin configuration editor

The admin-only `/admin/configuration` page offers a sectioned form and a raw
JSON view. Both can test and atomically save the full configuration. Existing
database passwords, session/CSRF secrets, bootstrap password hashes and metrics
bearer tokens are write-only: blank form fields or unchanged JSON placeholders
keep the saved value. Every successful save leaves a mode-0600,
timestamped `config.json.backup-*` copy beside the configured file and writes a
redacted audit log containing only the administrator account ID and changed
top-level sections.

Logging level/format and outbound-limit changes are applied live. Other changes deliberately do
not rebuild active listeners or security middleware; the page displays a
restart-required warning until GoMail starts with the saved file. Protect the
configuration directory because both the current file and previous copies may
contain secrets.

## Scale boundary

Current queue claiming is coordinated inside one process. Do not run multiple
GoMail application instances against one database. Mailbox, folder and search
views use indexed keyset pagination, but full high-volume/provider-scale
operation has not been validated.
