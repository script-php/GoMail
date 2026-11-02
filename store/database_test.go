package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gomail/config"
)

func TestSQLiteStartupAndAdditiveMigration(t *testing.T) {
	root := t.TempDir()
	cfg := config.StoreConfig{DBPath: filepath.Join(root, "mail.db"), AttachmentsPath: filepath.Join(root, "attachments")}
	db, err := OpenConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { db.Close() }()
	if db.IsMySQL() {
		t.Fatal("legacy config selected MySQL")
	}
	domain, err := db.CreateDomain(&Domain{Domain: "example.com", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`ALTER TABLE domains ADD COLUMN custom_note TEXT DEFAULT 'preserve me'`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`ALTER TABLE domains DROP COLUMN greylisting_delay_minutes`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`ALTER TABLE outbound_queue DROP COLUMN dsn_attempts`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`ALTER TABLE outbound_queue DROP COLUMN dsn_retry_at`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`ALTER TABLE outbound_queue_retention DROP COLUMN verp_days`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db, err = OpenConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var note string
	var delay int
	if err = db.QueryRow(`SELECT custom_note, greylisting_delay_minutes FROM domains WHERE id = ?`, domain).Scan(&note, &delay); err != nil {
		t.Fatal(err)
	}
	if note != "preserve me" || delay != 15 {
		t.Fatalf("migration lost data or default: %q %d", note, delay)
	}
	queueID, err := db.EnqueueMessage(&QueueEntry{MailFrom: "user@example.com", RcptTo: "remote@example.net", RawMessage: []byte("Subject: fixture\r\n\r\nbody"), MaxAttempts: 1, NextRetry: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	var attempts int
	var retryAt string
	if err = db.QueryRow(`SELECT dsn_attempts, dsn_retry_at FROM outbound_queue WHERE id = ?`, queueID).Scan(&attempts, &retryAt); err != nil || attempts != 0 || retryAt == "" {
		t.Fatalf("DSN retry columns not migrated: attempts=%d at=%q err=%v", attempts, retryAt, err)
	}
	var count int
	if err = db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = 'mailbox_folders_v1'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("migration history: %d %v", count, err)
	}
	if days, err := db.VERPRetentionDays(); err != nil || days != 0 {
		t.Fatalf("VERP retention column not migrated: %d %v", days, err)
	}
}

func TestMySQLSchemaParityAndConfiguration(t *testing.T) {
	db := &DB{}
	mysqlTables := map[string]map[string]bool{}
	for _, statement := range schemaStatements(mysqlSchemaSQL) {
		match := mysqlTablePattern.FindStringSubmatch(statement)
		if match == nil {
			if !mysqlIndexPattern.MatchString(statement) {
				t.Fatalf("unhandled schema statement: %s", statement)
			}
			continue
		}
		columns := map[string]bool{}
		for _, line := range strings.Split(statement, "\n")[1:] {
			if col := mysqlColumnPattern.FindStringSubmatch(strings.TrimSpace(line)); col != nil {
				columns[col[1]] = true
			}
		}
		mysqlTables[match[1]] = columns
	}
	sqliteTables := db.parseSchemaDefinition(schemaSQL)
	if len(sqliteTables) != len(mysqlTables) {
		t.Fatal("backend schemas have different tables")
	}
	for table, columns := range sqliteTables {
		if len(columns) != len(mysqlTables[table]) {
			t.Fatalf("column count differs for %s", table)
		}
		for column := range columns {
			if !mysqlTables[table][column] {
				t.Fatalf("MySQL missing %s.%s", table, column)
			}
		}
	}
	cfg := mysqlDriverConfig(config.MySQLConfig{Host: "::1", Port: 3306, User: "mail", Password: "p@ss:/?", Name: "gomail", TLS: "true"})
	if !cfg.ParseTime || cfg.Params["time_zone"] != "'+00:00'" || cfg.Addr != "[::1]:3306" || cfg.MultiStatements {
		t.Fatal("incorrect driver configuration")
	}
	if quoteMySQL("a`b") != "`a``b`" {
		t.Fatal("unsafe identifier quoting")
	}
}
