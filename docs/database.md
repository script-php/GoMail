# Database development

`store.OpenConfig` selects SQLite or MySQL from `config.StoreConfig`.
`store.Open(path, attachments)` remains available for SQLite callers. Business
queries use portable placeholders, UTC timestamp strings, and CURRENT_TIMESTAMP.
The few backend-specific upserts are selected with `db.IsMySQL()`; application SQL
is never rewritten with string substitutions by the database layer.

## Schemas and migrations

- `store/schema.sql`: SQLite schema.
- `store/schema_mysql.sql`: MySQL 8.0.13+ schema, using InnoDB, utf8mb4, BIGINT IDs,
  LONGTEXT email bodies and LONGBLOB raw messages.
- `store/db.go`: SQLite introspection and the shared data migration registry.
- `store/mysql_schema.go`: MySQL introspection and additive schema synchronization.
- `schema_migrations`: applied data migrations with application timestamps.

Keep logical columns in both schemas aligned. The parity regression test checks
that the table and column names match. MySQL requires indexable VARCHAR lengths,
explicit foreign keys, and expression defaults for TEXT. Nonunique Message-ID
indexes use a prefix; the full value is stored. The greylisting unique key omits
recipient_domain because the full recipient address already contains it.

Automatic synchronization creates missing tables, columns, indexes, and MySQL
table-level constraints. It does not remove extra columns or change existing
column types/defaults. Required MySQL columns without a default cannot be added
to populated tables automatically; use an explicit backfill migration. Adding a
unique or foreign-key constraint fails startup if existing data violates it.
Resolve inconsistent data explicitly rather than silently discarding it.

For data transformations or intentional type changes, add a uniquely named entry
to `RegisteredMigrations`. Check `db.IsMySQL()` for dialect-specific DDL. Migration
functions must be idempotent: completion is recorded only after success, and a
crash between completion and recording can cause a rerun. MySQL's implicit DDL
commits mean schema changes are not one transaction. An advisory lock prevents
simultaneous MySQL startup migrations; it does not make multiple delivery pools
safe against duplicate queue claims. Run one GoMail application instance per
database until queue claiming supports multiple processes.

System-generated reports (account ID zero) are queued without creating a mailbox
message. Their queue rows have no message foreign key. Normal outgoing messages
and their recipient queue entries commit in one transaction on either backend.

## Tests

`make test` runs all source-package tests, including SQLite initialization,
restart/additive migration, schema parity, config defaults, and mailbox behavior.
A live MySQL test is opt-in:

```bash
GOMAIL_TEST_MYSQL_ADDR=127.0.0.1:3307 \
GOMAIL_TEST_MYSQL_USER=root \
GOMAIL_TEST_MYSQL_PASSWORD='test-only-password' \
go test ./store -run TestMySQLIntegration -v
```

Use a disposable local server. The test creates a unique `gomail_test_*` database
and drops that database afterward. To use a database you created yourself, set
`GOMAIL_TEST_MYSQL_DATABASE=gomail`. That mode refuses populated or unrelated
tables, removes only its own test records, and leaves the initialized schema. Use
an empty test database with no concurrently running application. It checks
database/table creation, UTF-8 and
large binary mail, account isolation, queue/system reports, sessions, greylisting,
tarpitting, DMARC/TLS reports, missing-column/index upgrades, extra-column
preservation, migration history, reopening, and cascading account deletion.
No SQLite-to-MySQL data-transfer tool is included.

Driver details: [go-sql-driver/mysql](https://github.com/go-sql-driver/mysql).
MySQL schema rules: [data type defaults](https://dev.mysql.com/doc/refman/8.0/en/data-type-defaults.html).
