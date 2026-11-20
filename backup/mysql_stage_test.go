package backup

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gomail/config"
	"gomail/store"
)

func TestSQLiteRestoreStructureRejectsViewWithMatchingCount(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "struct.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE VIEW domains AS SELECT 1 AS id WHERE 0`); err != nil {
		t.Fatal(err)
	}
	if err := verifyStagedSnapshot(context.Background(), db, map[string]int64{"domains": 0, "accounts": 0, "messages": 0, "attachments": 0, "outbound_queue": 0, "outbound_queue_events": 0}, t.TempDir()); err == nil {
		// Other missing tables should also reject this snapshot; the structural
		// check below proves a view cannot masquerade as a counted base table.
		t.Fatal("incomplete snapshot accepted")
	}
	if err := verifySQLiteStructure(context.Background(), db, map[string]int64{"domains": 0}); err == nil {
		t.Fatal("view accepted as restored table")
	}
}

func TestSQLiteRestoreStructureRejectsBrokenReferences(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "foreign.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE domains (id INTEGER PRIMARY KEY); CREATE TABLE accounts (id INTEGER PRIMARY KEY, domain_id INTEGER REFERENCES domains(id)); INSERT INTO accounts(id, domain_id) VALUES (1, 99)`); err != nil {
		t.Fatal(err)
	}
	if err := verifySQLiteStructure(context.Background(), db, map[string]int64{"domains": 0, "accounts": 1}); err == nil || !strings.Contains(err.Error(), "foreign key") {
		t.Fatalf("orphaned account accepted: %v", err)
	}
}

func TestSQLiteRestoreStructureRejectsMissingCoreColumn(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "missing-column.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE domains (id INTEGER PRIMARY KEY, domain TEXT, is_active INTEGER);
		CREATE TABLE accounts (id INTEGER PRIMARY KEY, domain_id INTEGER, email TEXT, is_active INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if err := verifySQLiteStructure(context.Background(), db, map[string]int64{"domains": 0, "accounts": 0}); err == nil || !strings.Contains(err.Error(), "accounts.password_hash") {
		t.Fatalf("missing login column accepted or misidentified: %v", err)
	}
}

func TestSQLiteRestoreCoreColumnsAcceptsLiveSchema(t *testing.T) {
	root := t.TempDir()
	mailDB, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer mailDB.Close()
	if err := verifySQLiteCoreColumns(context.Background(), mailDB.DB); err != nil {
		t.Fatalf("current SQLite schema rejected: %v", err)
	}
	if err := verifySQLiteIdentityIndexes(context.Background(), mailDB.DB); err != nil {
		t.Fatalf("current SQLite identity indexes rejected: %v", err)
	}
	if err := verifySQLiteCoreForeignKeys(context.Background(), mailDB.DB); err != nil {
		t.Fatalf("current SQLite foreign keys rejected: %v", err)
	}
}

func TestSQLiteRestoreRequiresCoreForeignKeys(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "missing-fk.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE domains (id INTEGER PRIMARY KEY);
		CREATE TABLE accounts (id INTEGER PRIMARY KEY, domain_id INTEGER);
		CREATE TABLE folders (id INTEGER PRIMARY KEY, account_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE);
		CREATE TABLE messages (id INTEGER PRIMARY KEY, account_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE, folder_id INTEGER REFERENCES folders(id) ON DELETE SET NULL);
		CREATE TABLE attachments (id INTEGER PRIMARY KEY, message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE);
		CREATE TABLE outbound_queue (id INTEGER PRIMARY KEY, message_id INTEGER REFERENCES messages(id) ON DELETE SET NULL);
		CREATE TABLE outbound_queue_events (id INTEGER PRIMARY KEY, queue_id INTEGER REFERENCES outbound_queue(id) ON DELETE CASCADE)`); err != nil {
		t.Fatal(err)
	}
	if err := verifySQLiteCoreForeignKeys(context.Background(), db); err == nil || !strings.Contains(err.Error(), "accounts.domain_id") {
		t.Fatalf("missing domain ownership constraint accepted: %v", err)
	}
}

func TestSQLiteRestoreRejectsQueueCascade(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "queue-cascade.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE domains (id INTEGER PRIMARY KEY);
		CREATE TABLE accounts (id INTEGER PRIMARY KEY, domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE);
		CREATE TABLE folders (id INTEGER PRIMARY KEY, account_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE);
		CREATE TABLE messages (id INTEGER PRIMARY KEY, account_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE, folder_id INTEGER REFERENCES folders(id) ON DELETE SET NULL);
		CREATE TABLE attachments (id INTEGER PRIMARY KEY, message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE);
		CREATE TABLE outbound_queue (id INTEGER PRIMARY KEY, message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE);
		CREATE TABLE outbound_queue_events (id INTEGER PRIMARY KEY, queue_id INTEGER REFERENCES outbound_queue(id) ON DELETE CASCADE)`); err != nil {
		t.Fatal(err)
	}
	if err := verifySQLiteCoreForeignKeys(context.Background(), db); err == nil || !strings.Contains(err.Error(), "outbound_queue.message_id") {
		t.Fatalf("unsafe queue cascade accepted: %v", err)
	}
}

func TestSQLiteRestoreRejectsFolderCascade(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "folder-cascade.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE domains (id INTEGER PRIMARY KEY);
		CREATE TABLE accounts (id INTEGER PRIMARY KEY, domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE);
		CREATE TABLE folders (id INTEGER PRIMARY KEY, account_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE);
		CREATE TABLE messages (id INTEGER PRIMARY KEY, account_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE, folder_id INTEGER REFERENCES folders(id) ON DELETE CASCADE);
		CREATE TABLE attachments (id INTEGER PRIMARY KEY, message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE);
		CREATE TABLE outbound_queue (id INTEGER PRIMARY KEY, message_id INTEGER REFERENCES messages(id) ON DELETE SET NULL);
		CREATE TABLE outbound_queue_events (id INTEGER PRIMARY KEY, queue_id INTEGER REFERENCES outbound_queue(id) ON DELETE CASCADE)`); err != nil {
		t.Fatal(err)
	}
	if err := verifySQLiteCoreForeignKeys(context.Background(), db); err == nil || !strings.Contains(err.Error(), "messages.folder_id") {
		t.Fatalf("unsafe folder cascade accepted: %v", err)
	}
}

func TestSQLiteRestoreRequiresUniqueIdentityIndexes(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "identity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE domains (id INTEGER PRIMARY KEY, domain TEXT);
		CREATE TABLE accounts (id INTEGER PRIMARY KEY, email TEXT);
		CREATE UNIQUE INDEX domain_prefix_with_id ON domains(domain, id);
		CREATE UNIQUE INDEX account_email_unique ON accounts(email)`); err != nil {
		t.Fatal(err)
	}
	if err := verifySQLiteIdentityIndexes(context.Background(), db); err == nil || !strings.Contains(err.Error(), "domains.domain") {
		t.Fatalf("composite-only domain identity accepted: %v", err)
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX domain_unique ON domains(domain)`); err != nil {
		t.Fatal(err)
	}
	if err := verifySQLiteIdentityIndexes(context.Background(), db); err != nil {
		t.Fatalf("valid unique identities rejected: %v", err)
	}
	if _, err := db.Exec(`DROP INDEX account_email_unique`); err != nil {
		t.Fatal(err)
	}
	if err := verifySQLiteIdentityIndexes(context.Background(), db); err == nil || !strings.Contains(err.Error(), "accounts.email") {
		t.Fatalf("missing account identity accepted: %v", err)
	}
}

func TestStagedRestoreRequiresDistinctSafeDatabase(t *testing.T) {
	for _, name := range []string{"active", "ACTIVE", "other; DROP DATABASE active", "other.name", "-other", "", strings.Repeat("a", 65)} {
		if err := validateStagingDatabase("active", name); err == nil {
			t.Fatalf("unsafe staging database %q accepted", name)
		}
	}
	for _, name := range []string{"gomail_stage_01", "Stage2"} {
		if err := validateStagingDatabase("active", name); err != nil {
			t.Fatalf("valid staging database %q rejected: %v", name, err)
		}
	}
	cfg := &config.Config{Store: config.StoreConfig{Database: "sqlite"}}
	if _, err := RestoreStaged(cfg, "config.json", "backup.tar.gz", "stage", true); err == nil {
		t.Fatal("SQLite accepted MySQL staging database")
	}
}

func TestStagedAccountsMustBelongToTheirHostedDomain(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE domains (id INTEGER PRIMARY KEY, domain TEXT);
		CREATE TABLE accounts (id INTEGER PRIMARY KEY, domain_id INTEGER, email TEXT);
		INSERT INTO domains VALUES (1, 'example.test');
		INSERT INTO accounts VALUES (1, 1, 'alice@example.test')`); err != nil {
		t.Fatal(err)
	}
	if err := verifyStagedAccountDomains(context.Background(), db); err != nil {
		t.Fatalf("valid account rejected: %v", err)
	}
	if _, err := db.Exec(`UPDATE accounts SET email='alice@other.test' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := verifyStagedAccountDomains(context.Background(), db); err == nil {
		t.Fatal("restored account for an unhosted domain accepted")
	}
}

func TestStagedRestoreRejectsCaseVariantIdentities(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "identities.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE domains (domain TEXT UNIQUE);
		CREATE TABLE accounts (email TEXT UNIQUE);
		INSERT INTO domains VALUES ('Example.test'), ('example.test');
		INSERT INTO accounts VALUES ('alice@example.test')`); err != nil {
		t.Fatal(err)
	}
	if err := verifyStagedIdentityUniqueness(context.Background(), db); err == nil || !strings.Contains(err.Error(), "domains") {
		t.Fatalf("case-variant domains accepted: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM domains WHERE domain='Example.test';
		INSERT INTO accounts VALUES ('Alice@example.test')`); err != nil {
		t.Fatal(err)
	}
	if err := verifyStagedIdentityUniqueness(context.Background(), db); err == nil || !strings.Contains(err.Error(), "accounts") {
		t.Fatalf("case-variant accounts accepted: %v", err)
	}
}

func TestMySQLBackupRestoreCLIEnforcesConfiguredTLS(t *testing.T) {
	if got := mysqlClientTLSArgs(config.MySQLConfig{TLS: "true"}); len(got) != 1 || got[0] != "--ssl-mode=VERIFY_IDENTITY" {
		t.Fatalf("verified database TLS was not required by CLI: %v", got)
	}
	if got := mysqlClientTLSArgs(config.MySQLConfig{TLS: "false"}); len(got) != 0 {
		t.Fatalf("unexpected CLI TLS override: %v", got)
	}
}

func TestStagedMySQLRequiresCoreForeignKeys(t *testing.T) {
	core := []mysqlForeignKey{
		{table: "accounts", column: "domain_id", parent: "domains", parentColumn: "id", deleteRule: "CASCADE"},
		{table: "folders", column: "account_id", parent: "accounts", parentColumn: "id", deleteRule: "CASCADE"},
		{table: "messages", column: "account_id", parent: "accounts", parentColumn: "id", deleteRule: "CASCADE"},
		{table: "messages", column: "folder_id", parent: "folders", parentColumn: "id", deleteRule: "SET NULL"},
		{table: "attachments", column: "message_id", parent: "messages", parentColumn: "id", deleteRule: "CASCADE"},
		{table: "outbound_queue", column: "message_id", parent: "messages", parentColumn: "id", deleteRule: "SET NULL"},
		{table: "outbound_queue_events", column: "queue_id", parent: "outbound_queue", parentColumn: "id", deleteRule: "CASCADE"},
	}
	if err := requireCoreMySQLForeignKeys(core); err != nil {
		t.Fatalf("complete core schema rejected: %v", err)
	}
	for i := range core {
		missing := append([]mysqlForeignKey(nil), core[:i]...)
		missing = append(missing, core[i+1:]...)
		if err := requireCoreMySQLForeignKeys(missing); err == nil {
			t.Fatalf("missing core relationship %s.%s accepted", core[i].table, core[i].column)
		}
	}
	wrongAction := append([]mysqlForeignKey(nil), core...)
	wrongAction[5].deleteRule = "CASCADE"
	if err := requireCoreMySQLForeignKeys(wrongAction); err == nil {
		t.Fatal("unsafe MySQL queue cascade accepted")
	}
	wrongFolderAction := append([]mysqlForeignKey(nil), core...)
	wrongFolderAction[3].deleteRule = "CASCADE"
	if err := requireCoreMySQLForeignKeys(wrongFolderAction); err == nil {
		t.Fatal("unsafe MySQL folder cascade accepted")
	}
}

func TestStagedMySQLRequiresFullUniqueIdentityIndexes(t *testing.T) {
	valid := []mysqlIndexColumn{
		{table: "domains", index: "domain", column: "domain", position: 1},
		{table: "accounts", index: "email", column: "email", position: 1},
	}
	for _, table := range []string{"domains", "accounts", "folders", "messages", "attachments", "outbound_queue", "outbound_queue_events"} {
		valid = append(valid, mysqlIndexColumn{table: table, index: "PRIMARY", column: "id", position: 1})
	}
	if err := requireMySQLIdentityIndexes(valid); err != nil {
		t.Fatalf("valid identity indexes rejected: %v", err)
	}
	for name, mutate := range map[string]func([]mysqlIndexColumn) []mysqlIndexColumn{
		"missing domain": func(in []mysqlIndexColumn) []mysqlIndexColumn { return in[1:] },
		"missing primary key": func(in []mysqlIndexColumn) []mysqlIndexColumn {
			return append(in[:4], in[5:]...)
		},
		"composite primary key": func(in []mysqlIndexColumn) []mysqlIndexColumn {
			return append(in, mysqlIndexColumn{table: "accounts", index: "PRIMARY", column: "domain_id", position: 2})
		},
		"nonunique email": func(in []mysqlIndexColumn) []mysqlIndexColumn { in[1].nonUnique = true; return in },
		"prefix email": func(in []mysqlIndexColumn) []mysqlIndexColumn {
			in[1].prefixLength = sql.NullInt64{Int64: 20, Valid: true}
			return in
		},
		"composite email": func(in []mysqlIndexColumn) []mysqlIndexColumn {
			return append(in, mysqlIndexColumn{table: "accounts", index: "email", column: "id", position: 2})
		},
	} {
		t.Run(name, func(t *testing.T) {
			columns := mutate(append([]mysqlIndexColumn(nil), valid...))
			if err := requireMySQLIdentityIndexes(columns); err == nil {
				t.Fatal("unsafe identity index accepted")
			}
		})
	}
}

func TestStagedMySQLRequiresCoreColumnTypes(t *testing.T) {
	valid := append([]mysqlColumnShape(nil), requiredMySQLCoreColumns...)
	if err := requireMySQLCoreColumns(valid); err != nil {
		t.Fatalf("core columns rejected: %v", err)
	}
	for _, column := range []string{"accounts.password_hash", "messages.raw_message", "attachments.storage_path", "outbound_queue.raw_message", "outbound_queue.claim_token"} {
		t.Run(column, func(t *testing.T) {
			missing := make([]mysqlColumnShape, 0, len(valid)-1)
			for _, item := range valid {
				if item.table+"."+item.column != column {
					missing = append(missing, item)
				}
			}
			if err := requireMySQLCoreColumns(missing); err == nil {
				t.Fatal("missing core column accepted")
			}
		})
	}
	wrongType := append([]mysqlColumnShape(nil), valid...)
	for i := range wrongType {
		if wrongType[i].table == "messages" && wrongType[i].column == "raw_message" {
			wrongType[i].dataType = "varchar"
		}
	}
	if err := requireMySQLCoreColumns(wrongType); err == nil {
		t.Fatal("truncated raw-message column accepted")
	}
}

func TestSnapshotVerificationCoversNewAndLegacyManifests(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	counts, err := db.BackupCounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != len(store.BackupTables()) {
		t.Fatalf("manifest counts %d tables, schema list has %d", len(counts), len(store.BackupTables()))
	}
	if err := verifyStagedSnapshot(context.Background(), db.DB, counts, filepath.Join(root, "attachments")); err != nil {
		t.Fatal(err)
	}
	legacy := make(map[string]int64)
	for _, table := range stagedCountTables {
		legacy[table] = counts[table]
	}
	if err := verifyStagedSnapshot(context.Background(), db.DB, legacy, filepath.Join(root, "attachments")); err != nil {
		t.Fatalf("legacy six-count manifest rejected: %v", err)
	}
	counts["greylisting"]++
	if err := verifyStagedSnapshot(context.Background(), db.DB, counts, filepath.Join(root, "attachments")); err == nil {
		t.Fatal("non-core table count mismatch was not detected")
	}
	counts["greylisting"]--
	if _, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if err := verifyStagedSnapshot(context.Background(), db.DB, counts, filepath.Join(root, "attachments")); err == nil {
		t.Fatal("changed table count was not detected")
	}
	counts["unexpected_table"] = 0
	if err := verifyStagedSnapshot(context.Background(), db.DB, counts, filepath.Join(root, "attachments")); err == nil {
		t.Fatal("unknown manifest table accepted")
	}
}

func TestStagedAttachmentReferencesMustMatchFiles(t *testing.T) {
	root := t.TempDir()
	attachments := filepath.Join(root, "attachments")
	db, err := store.Open(filepath.Join(root, "mail.db"), attachments)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "a@example.test", PasswordHash: "x", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := db.GetFolderByType(accountID, "inbox")
	if err != nil || inbox == nil {
		t.Fatalf("inbox: %v %v", inbox, err)
	}
	messageID, err := db.SaveMessage(&store.Message{AccountID: accountID, FolderID: &inbox.ID, MessageID: "m1", Direction: "inbound", ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	attachmentID, err := db.SaveAttachment(&store.Attachment{MessageID: messageID, Filename: "file.bin", Size: 4, StoragePath: "file.bin"})
	if err != nil {
		t.Fatal(err)
	}
	check := func(wantError bool) {
		t.Helper()
		err := verifyStagedAttachments(context.Background(), db.DB, attachments)
		if (err != nil) != wantError {
			t.Fatalf("attachment verification error=%v, wantError=%v", err, wantError)
		}
	}
	check(true) // Missing file.
	file := filepath.Join(attachments, "file.bin")
	if err := os.WriteFile(file, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	check(false)
	if _, err := db.Exec(`UPDATE attachments SET size=5 WHERE id=?`, attachmentID); err != nil {
		t.Fatal(err)
	}
	check(true)
	if _, err := db.Exec(`UPDATE attachments SET size=4, storage_path='../outside' WHERE id=?`, attachmentID); err != nil {
		t.Fatal(err)
	}
	check(true)
	if _, err := db.Exec(`UPDATE attachments SET storage_path='file.bin' WHERE id=?`, attachmentID); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "outside"), file); err != nil {
		t.Fatal(err)
	}
	check(true)
}
