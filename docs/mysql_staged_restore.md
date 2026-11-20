# Staged MySQL restore design

Status: an opt-in staged import and config switch are implemented with
`-restore-stage-db`. The operator must pre-provision a distinct empty database
accessible to the configured user. The ordinary MySQL restore still imports
into the configured database for compatibility. Automatic rollback and phase-by-
phase crash recovery remain design work. Final-phase completion is implemented: when the marker says `durable`, startup re-verifies both the restored and pre-restore safety archives, active database counts and attachment references before clearing it. Earlier phases or failed verification still block startup. The staged path now retains the old
attachment and ACME directory generations and records their paths in the
incomplete-restore marker before activation. It verifies manifest table counts, requires counted objects to be base tables, checks core authentication, mailbox, attachment, and outbound-queue column types, checks installed single-column foreign keys for orphaned rows, and checks every attachment
reference against the staged tree. It also requires full-column unique indexes
for domain and account-email identities and the core account, message,
attachment, and queue foreign-key relationships before checking installed
constraints for orphaned rows, but still needs a live two-database crash
drill and full schema validation before it should
be treated as a complete atomic restore.
Both MySQL and SQLite restore now write a durable `.restore-incomplete` marker
beside the config before their first mutation, and normal startup refuses to
serve while that marker exists. After a
failed restore, keep the service stopped, inspect the safety-archive path in
the marker, recover and verify the database and filesystem generation, then
remove the marker manually. Do not remove it merely to make startup succeed.
This safeguard does not make the restore atomic or perform automatic rollback.
The marker records the last durably completed phase (database import,
attachment/ACME activation, TLS files, configuration, or final sync). A phase
can lag a mutation if a crash occurs before its marker update; inspect the
actual files and database state before recovery.

## The failure to prevent

`Restore` currently stages files, imports SQL into the active MySQL database,
then activates attachments, ACME files, TLS files, and configuration. An import
or later filesystem failure can leave the database and files from different
points in time. The pre-restore archive provides recovery, but recovery is
manual. A staged replacement must never allow the service to start while those
generations are mixed.

## Proposed mechanism

1. Require an offline instance lock and a verified archive. Create and verify
   the pre-restore safety archive before any mutation. Reject a restore if a
   prior restore journal is unresolved.
2. Import the SQL dump into a distinct, empty staging database. The current
   opt-in path requires it to be pre-provisioned and refuses to create or drop
   it. It validates every table count present in the manifest and each
   attachment reference against the staged tree before activation. Full
   schema and migration validation remain to be added.
3. Stage attachment, ACME, TLS, and configuration files on their destination
   filesystems. The staged configuration must refer to the staged database and
   the *destination* paths and credentials, not blindly reuse source-host
   database names or paths stored in the archive. Reject incompatible restored
   settings before the switch.
4. Write and sync a local restore journal recording the old and new database
   names, all staged/active/previous filesystem paths, the archive identity,
   and the phase. Rename existing filesystem trees to retained previous paths,
   activate the staged trees, then atomically replace the active configuration
   file to point at the staged database. Sync the parent directories and update
   the journal after each durable phase. Keep the old database and files until
   post-switch verification succeeds.
5. On startup, before opening listeners, inspect the journal. Finish or roll
   back an incomplete switch using its recorded phase. If that cannot be done
   unambiguously, refuse startup and show a recovery instruction. Do not serve
   mail from a database whose referenced attachment generation is absent.
6. After successful startup/restore verification, retain the safety archive
   and old database for an operator-defined window. Cleanup must never target
   a database solely by a name read from an archive or journal; validate its
   generated identity and disallow the configured active database.

The config-file switch is the logical commit point, but MySQL and filesystem
renames do not share a transaction. The journal plus fail-closed startup is
therefore required; merely importing into another database is insufficient.
The restore command should not claim success until all phases and verification
complete.

## Test prerequisites and acceptance cases

The current local `gomailtest` account has privileges only on `gomailtest.*`.
It cannot access the separate staging database needed for this design. A
separate disposable test grant (or two pre-provisioned test databases with
appropriate grants) is required before implementing the switch. Tests must
prove: failed import leaves the active generation intact; failure after each
file rename recovers on restart; failure before and after config activation
never starts with mixed generations; source and destination database names and
paths differ safely; cleanup cannot drop an active database; successful restore
preserves queue history and attachments. The existing fixed-database round trip
does not cover these crash and switch cases.
