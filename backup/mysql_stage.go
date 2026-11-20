package backup

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"gomail/config"
	"gomail/store"
)

var stagingDatabaseName = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

var stagedCountTables = []string{"domains", "accounts", "messages", "attachments", "outbound_queue", "outbound_queue_events"}

type mysqlForeignKey struct{ table, constraint, column, parentSchema, parent, parentColumn, deleteRule string }

type mysqlIndexColumn struct {
	table, index, column string
	position             int
	nonUnique            bool
	prefixLength         sql.NullInt64
}

type mysqlColumnShape struct{ table, column, dataType string }

// These columns are read before or during core authentication, mailbox access,
// attachment serving, and queued delivery. A dump with matching row counts
// but an incompatible definition must not become the active database.
var requiredMySQLCoreColumns = []mysqlColumnShape{
	{"domains", "id", "bigint"}, {"domains", "domain", "varchar"}, {"domains", "is_active", "bigint"},
	{"accounts", "id", "bigint"}, {"accounts", "domain_id", "bigint"}, {"accounts", "email", "varchar"}, {"accounts", "password_hash", "varchar"}, {"accounts", "is_active", "bigint"},
	{"folders", "id", "bigint"}, {"folders", "account_id", "bigint"}, {"folders", "folder_type", "varchar"},
	{"messages", "id", "bigint"}, {"messages", "account_id", "bigint"}, {"messages", "folder_id", "bigint"}, {"messages", "raw_message", "longblob"},
	{"attachments", "id", "bigint"}, {"attachments", "message_id", "bigint"}, {"attachments", "storage_path", "longtext"}, {"attachments", "size", "bigint"},
	{"outbound_queue", "id", "bigint"}, {"outbound_queue", "message_id", "bigint"}, {"outbound_queue", "mail_from", "varchar"}, {"outbound_queue", "rcpt_to", "longtext"}, {"outbound_queue", "raw_message", "longblob"}, {"outbound_queue", "status", "varchar"}, {"outbound_queue", "claim_token", "varchar"},
	{"outbound_queue_events", "id", "bigint"}, {"outbound_queue_events", "queue_id", "bigint"},
}

// The external MySQL utilities must not silently downgrade a configured
// verified TLS connection to their default opportunistic SSL mode.
func mysqlClientTLSArgs(cfg config.MySQLConfig) []string {
	if cfg.TLS == "true" {
		return []string{"--ssl-mode=VERIFY_IDENTITY"}
	}
	return nil
}

func validateStagingDatabase(active, staged string) error {
	if !stagingDatabaseName.MatchString(staged) {
		return fmt.Errorf("staging database name must contain only ASCII letters, digits, or underscores (1-64 characters)")
	}
	if strings.EqualFold(active, staged) {
		return fmt.Errorf("staging database must differ from the active database")
	}
	return nil
}

func openStageDatabase(cfg config.MySQLConfig) (*sql.DB, error) {
	driver := mysql.NewConfig()
	driver.User, driver.Passwd, driver.DBName = cfg.User, cfg.Password, cfg.Name
	driver.Net, driver.Addr = "tcp", net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	driver.TLSConfig = cfg.TLS
	driver.Timeout, driver.ReadTimeout, driver.WriteTimeout = 10*time.Second, 30*time.Second, 30*time.Second
	connector, err := mysql.NewConnector(driver)
	if err != nil {
		return nil, fmt.Errorf("configuring staging database connection: %w", err)
	}
	return sql.OpenDB(connector), nil
}

func checkEmptyStagingDatabase(cfg config.MySQLConfig, stage string) error {
	cfg.Name = stage
	db, err := openStageDatabase(cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("staging database %s must exist and be accessible: %w", stage, err)
	}
	var objects int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = ?`, stage).Scan(&objects); err != nil {
		return fmt.Errorf("checking staging database %s: %w", stage, err)
	}
	if objects != 0 {
		return fmt.Errorf("staging database %s is not empty (%d tables or views); refusing to overwrite it", stage, objects)
	}
	return nil
}

func verifyStagedMySQL(cfg config.MySQLConfig, expected map[string]int64, attachmentsPath string) error {
	db, err := openStageDatabase(cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := verifyMySQLTableStructure(ctx, db, expected); err != nil {
		return err
	}
	return verifyStagedSnapshot(ctx, db, expected, attachmentsPath)
}

func verifyMySQLTableStructure(ctx context.Context, db *sql.DB, expected map[string]int64) error {
	for table := range expected {
		if !isKnownBackupTable(table) {
			return fmt.Errorf("unknown backup table %q", table)
		}
		var kind string
		if err := db.QueryRowContext(ctx, `SELECT TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?`, table).Scan(&kind); err != nil {
			return fmt.Errorf("checking restored table %s: %w", table, err)
		}
		if kind != "BASE TABLE" {
			return fmt.Errorf("restored %s is %s, not a base table", table, kind)
		}
	}
	if err := verifyMySQLCoreColumns(ctx, db); err != nil {
		return err
	}
	if err := verifyMySQLIdentityIndexes(ctx, db); err != nil {
		return err
	}
	return verifyMySQLForeignKeys(ctx, db)
}

func verifyMySQLCoreColumns(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE()`)
	if err != nil {
		return fmt.Errorf("loading restored MySQL columns: %w", err)
	}
	var actual []mysqlColumnShape
	for rows.Next() {
		var column mysqlColumnShape
		if err := rows.Scan(&column.table, &column.column, &column.dataType); err != nil {
			rows.Close()
			return err
		}
		actual = append(actual, column)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	return requireMySQLCoreColumns(actual)
}

func requireMySQLCoreColumns(actual []mysqlColumnShape) error {
	columns := make(map[string]string, len(actual))
	for _, column := range actual {
		columns[column.table+"."+column.column] = column.dataType
	}
	for _, required := range requiredMySQLCoreColumns {
		key := required.table + "." + required.column
		if got := columns[key]; got != required.dataType {
			return fmt.Errorf("restored MySQL schema has incompatible %s: type %q, need %q", key, got, required.dataType)
		}
	}
	return nil
}

// Core rows must retain their primary keys, and domain/account lookups must
// have unambiguous identities. Counts and foreign keys alone cannot detect a
// dump with these constraints removed.
func verifyMySQLIdentityIndexes(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT TABLE_NAME, INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, COLUMN_NAME, SUB_PART
		FROM information_schema.STATISTICS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN ('domains', 'accounts', 'folders', 'messages', 'attachments', 'outbound_queue', 'outbound_queue_events')`)
	if err != nil {
		return fmt.Errorf("loading restored MySQL identity indexes: %w", err)
	}
	var columns []mysqlIndexColumn
	for rows.Next() {
		var entry mysqlIndexColumn
		var nonUnique int
		var column sql.NullString
		if err := rows.Scan(&entry.table, &entry.index, &nonUnique, &entry.position, &column, &entry.prefixLength); err != nil {
			rows.Close()
			return err
		}
		entry.nonUnique, entry.column = nonUnique != 0, column.String
		columns = append(columns, entry)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	return requireMySQLIdentityIndexes(columns)
}

func requireMySQLIdentityIndexes(columns []mysqlIndexColumn) error {
	for _, table := range []string{"domains", "accounts", "folders", "messages", "attachments", "outbound_queue", "outbound_queue_events"} {
		found := false
		for _, column := range columns {
			if column.table == table && column.index == "PRIMARY" && column.column == "id" && column.position == 1 && !column.nonUnique && !column.prefixLength.Valid {
				found = true
				for _, other := range columns {
					if other.table == table && other.index == "PRIMARY" && other.position != 1 {
						found = false
					}
				}
				break
			}
		}
		if !found {
			return fmt.Errorf("restored MySQL schema lacks a single-column primary key on %s.id", table)
		}
	}
	for _, want := range []struct{ table, column string }{{"domains", "domain"}, {"accounts", "email"}} {
		found := false
		for _, candidate := range columns {
			if candidate.table != want.table || candidate.column != want.column || candidate.nonUnique || candidate.position != 1 || candidate.prefixLength.Valid {
				continue
			}
			onlyColumn := true
			for _, other := range columns {
				if other.table == candidate.table && other.index == candidate.index && other.position != 1 {
					onlyColumn = false
					break
				}
			}
			if onlyColumn {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("restored MySQL schema lacks a full-column unique index on %s.%s", want.table, want.column)
		}
	}
	return nil
}

// MySQL does not retroactively check rows inserted while FOREIGN_KEY_CHECKS
// was disabled by a dump. Check every installed single-column relationship
// before activating the imported generation.
func verifyMySQLForeignKeys(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT k.TABLE_NAME, k.CONSTRAINT_NAME, k.COLUMN_NAME, k.REFERENCED_TABLE_SCHEMA, k.REFERENCED_TABLE_NAME, k.REFERENCED_COLUMN_NAME, r.DELETE_RULE
		FROM information_schema.KEY_COLUMN_USAGE k
		JOIN information_schema.REFERENTIAL_CONSTRAINTS r ON r.CONSTRAINT_SCHEMA=k.TABLE_SCHEMA AND r.TABLE_NAME=k.TABLE_NAME AND r.CONSTRAINT_NAME=k.CONSTRAINT_NAME
		WHERE k.TABLE_SCHEMA = DATABASE() AND k.REFERENCED_TABLE_NAME IS NOT NULL`)
	if err != nil {
		return fmt.Errorf("loading restored foreign keys: %w", err)
	}
	var relations []mysqlForeignKey
	for rows.Next() {
		var r mysqlForeignKey
		if err := rows.Scan(&r.table, &r.constraint, &r.column, &r.parentSchema, &r.parent, &r.parentColumn, &r.deleteRule); err != nil {
			rows.Close()
			return err
		}
		relations = append(relations, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if err := requireCoreMySQLForeignKeys(relations); err != nil {
		return err
	}
	var activeSchema string
	if err := db.QueryRowContext(ctx, `SELECT DATABASE()`).Scan(&activeSchema); err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, r := range relations {
		if r.parentSchema != activeSchema {
			return fmt.Errorf("restored relationship %s.%s references another database", r.table, r.constraint)
		}
		key := r.table + "\x00" + r.constraint
		if seen[key] {
			return fmt.Errorf("restored composite relationship %s.%s requires explicit verification", r.table, r.constraint)
		}
		seen[key] = true
	}
	for _, r := range relations {
		// Metadata supplies identifiers; quote each component before building SQL.
		query := "SELECT EXISTS (SELECT 1 FROM `" + strings.ReplaceAll(r.table, "`", "``") + "` child LEFT JOIN `" + strings.ReplaceAll(r.parent, "`", "``") + "` parent ON child.`" + strings.ReplaceAll(r.column, "`", "``") + "` = parent.`" + strings.ReplaceAll(r.parentColumn, "`", "``") + "` WHERE child.`" + strings.ReplaceAll(r.column, "`", "``") + "` IS NOT NULL AND parent.`" + strings.ReplaceAll(r.parentColumn, "`", "``") + "` IS NULL LIMIT 1)"
		var orphan bool
		if err := db.QueryRowContext(ctx, query).Scan(&orphan); err != nil {
			return fmt.Errorf("checking restored relationship %s.%s: %w", r.table, r.column, err)
		}
		if orphan {
			return fmt.Errorf("restored relationship %s.%s references missing %s.%s", r.table, r.column, r.parent, r.parentColumn)
		}
	}
	return nil
}

// An imported dump can omit constraints entirely. Checking only the foreign
// keys that happen to be installed would then report no orphaned rows and
// allow a structurally broken mail store to become active.
func requireCoreMySQLForeignKeys(relations []mysqlForeignKey) error {
	required := []struct{ table, column, parent, parentColumn, deleteRule string }{
		{"accounts", "domain_id", "domains", "id", "CASCADE"},
		{"folders", "account_id", "accounts", "id", "CASCADE"},
		{"messages", "account_id", "accounts", "id", "CASCADE"},
		{"messages", "folder_id", "folders", "id", "SET NULL"},
		{"attachments", "message_id", "messages", "id", "CASCADE"},
		{"outbound_queue", "message_id", "messages", "id", "SET NULL"},
		{"outbound_queue_events", "queue_id", "outbound_queue", "id", "CASCADE"},
	}
	for _, want := range required {
		found := false
		for _, got := range relations {
			if got.table == want.table && got.column == want.column && got.parent == want.parent && got.parentColumn == want.parentColumn && got.deleteRule == want.deleteRule {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("restored MySQL schema lacks required foreign key %s.%s -> %s.%s ON DELETE %s", want.table, want.column, want.parent, want.parentColumn, want.deleteRule)
		}
	}
	return nil
}

func verifySQLiteStructure(ctx context.Context, db *sql.DB, expected map[string]int64) error {
	var result string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil {
		return fmt.Errorf("checking restored SQLite integrity: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("restored SQLite integrity check failed: %s", result)
	}
	var foreignTable string
	if err := db.QueryRowContext(ctx, `SELECT "table" FROM pragma_foreign_key_check LIMIT 1`).Scan(&foreignTable); err == nil {
		return fmt.Errorf("restored SQLite foreign key violation in %s", foreignTable)
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("checking restored SQLite foreign keys: %w", err)
	}
	for table := range expected {
		if !isKnownBackupTable(table) {
			return fmt.Errorf("unknown backup table %q", table)
		}
		var kind string
		if err := db.QueryRowContext(ctx, `SELECT type FROM sqlite_master WHERE name = ?`, table).Scan(&kind); err != nil {
			return fmt.Errorf("checking restored table %s: %w", table, err)
		}
		if kind != "table" {
			return fmt.Errorf("restored %s is %s, not a table", table, kind)
		}
	}
	if err := verifySQLiteCoreColumns(ctx, db); err != nil {
		return err
	}
	if err := verifySQLiteIdentityIndexes(ctx, db); err != nil {
		return err
	}
	return verifySQLiteCoreForeignKeys(ctx, db)
}

// Row counts and PRAGMA integrity_check do not establish that the restored
// schema has the columns needed to authenticate, read mail, or resume delivery.
func verifySQLiteCoreColumns(ctx context.Context, db *sql.DB) error {
	columns := make(map[string]bool)
	seenTables := make(map[string]bool)
	for _, required := range requiredMySQLCoreColumns {
		if seenTables[required.table] {
			continue
		}
		seenTables[required.table] = true
		// Table names come only from the fixed core-column list above.
		rows, err := db.QueryContext(ctx, "PRAGMA table_info(`"+required.table+"`)")
		if err != nil {
			return fmt.Errorf("checking restored SQLite table %s: %w", required.table, err)
		}
		for rows.Next() {
			var cid, notNull, primaryKey int
			var name, dataType string
			var defaultValue sql.NullString
			if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
				rows.Close()
				return err
			}
			columns[required.table+"."+name] = true
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("reading restored SQLite table %s: %w", required.table, err)
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	for _, required := range requiredMySQLCoreColumns {
		key := required.table + "." + required.column
		if !columns[key] {
			return fmt.Errorf("restored SQLite schema lacks required column %s", key)
		}
	}
	return nil
}

// A restored database without unique domain/account identities may have valid
// rows today but admit ambiguous addresses after GoMail starts accepting mail.
func verifySQLiteIdentityIndexes(ctx context.Context, db *sql.DB) error {
	for _, want := range []struct{ table, column string }{{"domains", "domain"}, {"accounts", "email"}} {
		rows, err := db.QueryContext(ctx, `SELECT name FROM pragma_index_list(?) WHERE "unique" = 1 AND partial = 0`, want.table)
		if err != nil {
			return fmt.Errorf("loading restored SQLite indexes for %s: %w", want.table, err)
		}
		var names []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			names = append(names, name)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		found := false
		for _, name := range names {
			indexRows, err := db.QueryContext(ctx, `SELECT name FROM pragma_index_info(?)`, name)
			if err != nil {
				return fmt.Errorf("checking restored SQLite index %s: %w", name, err)
			}
			var columns []string
			for indexRows.Next() {
				var column sql.NullString
				if err := indexRows.Scan(&column); err != nil {
					indexRows.Close()
					return err
				}
				columns = append(columns, column.String)
			}
			if err := indexRows.Err(); err != nil {
				indexRows.Close()
				return err
			}
			if err := indexRows.Close(); err != nil {
				return err
			}
			if len(columns) == 1 && columns[0] == want.column {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("restored SQLite schema lacks a full unique index on %s.%s", want.table, want.column)
		}
	}
	return nil
}

// foreign_key_check checks rows against installed rules, so an imported
// snapshot that omits a rule entirely would otherwise pass it trivially.
func verifySQLiteCoreForeignKeys(ctx context.Context, db *sql.DB) error {
	for _, want := range []struct{ table, column, parent, parentColumn, deleteRule string }{
		{"accounts", "domain_id", "domains", "id", "CASCADE"},
		{"folders", "account_id", "accounts", "id", "CASCADE"},
		{"messages", "account_id", "accounts", "id", "CASCADE"},
		{"messages", "folder_id", "folders", "id", "SET NULL"},
		{"attachments", "message_id", "messages", "id", "CASCADE"},
		{"outbound_queue", "message_id", "messages", "id", "SET NULL"},
		{"outbound_queue_events", "queue_id", "outbound_queue", "id", "CASCADE"},
	} {
		rows, err := db.QueryContext(ctx, `SELECT "from", "table", "to", on_delete FROM pragma_foreign_key_list(?)`, want.table)
		if err != nil {
			return fmt.Errorf("loading restored SQLite foreign keys for %s: %w", want.table, err)
		}
		found := false
		for rows.Next() {
			var column, parent, parentColumn, deleteRule string
			if err := rows.Scan(&column, &parent, &parentColumn, &deleteRule); err != nil {
				rows.Close()
				return err
			}
			if column == want.column && parent == want.parent && parentColumn == want.parentColumn && deleteRule == want.deleteRule {
				found = true
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("restored SQLite schema lacks required foreign key %s.%s -> %s.%s ON DELETE %s", want.table, want.column, want.parent, want.parentColumn, want.deleteRule)
		}
	}
	return nil
}

func verifyStagedSnapshot(ctx context.Context, db *sql.DB, expected map[string]int64, attachmentsPath string) error {
	// Older archives contain only these six counts. Accept those archives,
	// but verify every additional table present in newer manifests.
	for _, table := range stagedCountTables {
		if _, ok := expected[table]; !ok {
			return fmt.Errorf("archive manifest lacks %s count", table)
		}
	}
	for table, want := range expected {
		if !isKnownBackupTable(table) {
			return fmt.Errorf("archive manifest contains unknown table %q", table)
		}
		var got int64
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+table+"`").Scan(&got); err != nil {
			return fmt.Errorf("verifying staged %s table: %w", table, err)
		}
		if got != want {
			return fmt.Errorf("staged %s row count %d differs from archive count %d", table, got, want)
		}
	}
	if err := verifyStagedAccountDomains(ctx, db); err != nil {
		return err
	}
	if err := verifyStagedIdentityUniqueness(ctx, db); err != nil {
		return err
	}
	return verifyStagedAttachments(ctx, db, attachmentsPath)
}

// The MySQL schema uses a binary collation, and SQLite can also hold
// case-variants when data was imported directly. GoMail resolves hosted
// identities case-insensitively, so reject an ambiguous restore before switch.
func verifyStagedIdentityUniqueness(ctx context.Context, db *sql.DB) error {
	for _, source := range []struct{ table, column string }{{"domains", "domain"}, {"accounts", "email"}} {
		rows, err := db.QueryContext(ctx, "SELECT "+source.column+" FROM "+source.table)
		if err != nil {
			return fmt.Errorf("loading staged %s identities: %w", source.table, err)
		}
		seen := make(map[string]struct{})
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				rows.Close()
				return err
			}
			key := strings.ToLower(value)
			if _, exists := seen[key]; exists {
				rows.Close()
				return fmt.Errorf("staged %s has identities differing only by case: %q", source.table, value)
			}
			seen[key] = struct{}{}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func verifyStagedAccountDomains(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT a.id, a.email, d.domain FROM accounts a JOIN domains d ON d.id=a.domain_id`)
	if err != nil {
		return fmt.Errorf("loading staged account addresses: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var address, domain string
		if err := rows.Scan(&id, &address, &domain); err != nil {
			return err
		}
		parsed, parseErr := mail.ParseAddress(address)
		parts := strings.Split(address, "@")
		if parseErr != nil || parsed.Address != address || len(parts) != 2 || parts[0] == "" || store.ValidateMailDomain(parts[1]) != nil || !strings.EqualFold(parts[1], domain) {
			return fmt.Errorf("staged account %d address does not belong to its hosted domain", id)
		}
	}
	return rows.Err()
}

func isKnownBackupTable(table string) bool {
	for _, known := range store.BackupTables() {
		if table == known {
			return true
		}
	}
	return false
}

// Every persisted attachment reference must resolve to an actual regular file
// in the tree being activated. This catches inconsistent archives and legacy
// absolute paths before the configuration points at the staged database.
func verifyStagedAttachments(ctx context.Context, db *sql.DB, root string) error {
	rows, err := db.QueryContext(ctx, `SELECT id, storage_path, size FROM attachments`)
	if err != nil {
		return fmt.Errorf("loading staged attachment references: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, size int64
		var name string
		if err := rows.Scan(&id, &name, &size); err != nil {
			return err
		}
		if name == "" || name == "." || name == ".." || filepath.Base(name) != name || !filepath.IsLocal(name) {
			return fmt.Errorf("staged attachment %d has unsafe or non-portable storage path %q", id, name)
		}
		info, err := os.Lstat(filepath.Join(root, name))
		if err != nil {
			return fmt.Errorf("staged attachment %d file %q is unavailable: %w", id, name, err)
		}
		if !info.Mode().IsRegular() || size < 0 || info.Size() != size {
			return fmt.Errorf("staged attachment %d file %q is not a regular file of the recorded size", id, name)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("reading staged attachment references: %w", err)
	}
	return nil
}
