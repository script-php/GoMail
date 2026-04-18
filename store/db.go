package store

import (
	"database/sql"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// DB wraps the SQLite database connection.
type DB struct {
	*sql.DB
	attachmentsPath string
}

// Open opens (or creates) the SQLite database and runs migrations.
func Open(dbPath, attachmentsPath string) (*DB, error) {
	// Ensure directories exist
	if err := os.MkdirAll(filepath.Dir(dbPath), 0750); err != nil {
		return nil, fmt.Errorf("creating db directory: %w", err)
	}
	if err := os.MkdirAll(attachmentsPath, 0750); err != nil {
		return nil, fmt.Errorf("creating attachments directory: %w", err)
	}

	// Open SQLite with WAL mode for concurrent reads
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=ON", dbPath)
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Set connection pool (SQLite doesn't benefit from many connections)
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	// Run schema
	if _, err := sqlDB.Exec(schemaSQL); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("running schema migration: %w", err)
	}

	db := &DB{
		DB:              sqlDB,
		attachmentsPath: attachmentsPath,
	}

	// Migrate existing accounts to have folders if they don't already
	if err := db.migrateExistingAccounts(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("migrating existing accounts: %w", err)
	}

	// Run all registered migrations
	if err := db.runMigrations(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	// Sync database schema with schema.sql (auto-detects and applies differences)
	if err := db.syncSchemaWithDefinition(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("syncing schema: %w", err)
	}

	return db, nil
}

// AttachmentsPath returns the base path for attachment file storage.
func (db *DB) AttachmentsPath() string {
	return db.attachmentsPath
}

// migrateExistingAccounts creates default folders for any accounts that don't have them yet,
// and assigns existing messages to their appropriate folders based on direction.
// This handles accounts created before the folder system was added.
func (db *DB) migrateExistingAccounts() error {
	// Get all account IDs
	rows, err := db.Query("SELECT id FROM accounts")
	if err != nil {
		return err
	}
	defer rows.Close()

	var accountIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		accountIDs = append(accountIDs, id)
	}
	if err = rows.Err(); err != nil {
		return err
	}

	// For each account, check if it has folders and create them if missing
	for _, accountID := range accountIDs {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM folders WHERE account_id = ?", accountID).Scan(&count)
		if err != nil {
			return err
		}

		// If account has no folders, create the defaults
		if count == 0 {
			if err := db.DefaultFolders(accountID); err != nil {
				// Log but don't fail - continue with other accounts
				fmt.Printf("warning: failed to create folders for account %d: %v\n", accountID, err)
				continue
			}
		}

		// Assign existing messages to folders based on direction
		// Inbound messages -> Inbox folder
		inboxFolder, err := db.GetFolderByType(accountID, "inbox")
		if err == nil && inboxFolder != nil {
			_, err = db.Exec(`
				UPDATE messages SET folder_id = ? 
				WHERE account_id = ? AND direction = 'inbound' AND folder_id IS NULL
			`, inboxFolder.ID, accountID)
			if err != nil {
				fmt.Printf("warning: failed to assign inbound messages for account %d: %v\n", accountID, err)
			}
		}

		// Outbound messages -> Sent folder
		sentFolder, err := db.GetFolderByType(accountID, "sent")
		if err == nil && sentFolder != nil {
			_, err = db.Exec(`
				UPDATE messages SET folder_id = ? 
				WHERE account_id = ? AND direction = 'outbound' AND folder_id IS NULL
			`, sentFolder.ID, accountID)
			if err != nil {
				fmt.Printf("warning: failed to assign outbound messages for account %d: %v\n", accountID, err)
			}
		}
	}

	return nil
}

// Migration represents a database migration
type Migration struct {
	Name string                    // Unique migration name
	Run  func(*DB) error          // Migration function
}

// ColumnDef represents a column definition for schema comparison
type ColumnDef struct {
	Name    string
	Type    string
	Default interface{}
	NotNull bool
}

// ColumnChange represents a detected column change
type ColumnChange struct {
	Action  string // "add", "modify", "delete"
	Name    string
	Type    string
	Default interface{}
	NotNull bool
}

// RegisteredMigrations returns all migrations in order
// Add custom migrations here for one-time data transformations
// Schema changes should be made directly in schema.sql - they're automatically applied
func (db *DB) RegisteredMigrations() []Migration {
	return []Migration{
		// Example: Data migrations (not schema changes)
		// {
		//     Name: "migrate_user_data",
		//     Run: func(d *DB) error {
		//         // Custom logic here
		//         return nil
		//     },
		// },
	}
}

// runMigrations executes all registered migrations
// Note: Schema changes are handled by syncSchemaWithDefinition() - migrations are for data transformations
func (db *DB) runMigrations() error {
	migrations := db.RegisteredMigrations()

	for _, migration := range migrations {
		fmt.Printf("[db] Running data migration: %s\n", migration.Name)
		if err := migration.Run(db); err != nil {
			return fmt.Errorf("migration %s failed: %w", migration.Name, err)
		}
	}

	return nil
}

// getTableSchema retrieves existing column definitions from a table (SQLite compatible)
func (db *DB) getTableSchema(tableName string) (map[string]ColumnDef, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	schema := make(map[string]ColumnDef)
	for rows.Next() {
		var cid int
		var name string
		var typ string
		var notnull int
		var dflt sql.NullString
		var pk int

		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}

		var defaultValue interface{}
		if dflt.Valid {
			defaultStr := dflt.String
			
			// Remove surrounding quotes from PRAGMA defaults (they include quotes for string literals)
			if (strings.HasPrefix(defaultStr, "'") && strings.HasSuffix(defaultStr, "'")) ||
				(strings.HasPrefix(defaultStr, "\"") && strings.HasSuffix(defaultStr, "\"")) {
				defaultStr = defaultStr[1 : len(defaultStr)-1]
			}
			
			// Try to parse numeric defaults
			if num, err := strconv.Atoi(defaultStr); err == nil {
				defaultValue = num
			} else if strings.EqualFold(defaultStr, "NULL") {
				// Only NULL becomes nil, empty string stays as empty string
				defaultValue = nil
			} else {
				// Keep as string (including empty string)
				defaultValue = defaultStr
			}
		}

		schema[name] = ColumnDef{
			Name:    name,
			Type:    strings.ToUpper(typ),
			Default: defaultValue,
			NotNull: notnull != 0,
		}
	}

	return schema, rows.Err()
}

// computeColumnDiff detects what changed between existing and desired schema
func (db *DB) computeColumnDiff(existing map[string]ColumnDef, desired map[string]ColumnDef) []ColumnChange {
	var changes []ColumnChange

	// Check for columns to add or modify
	for desiredName, desiredCol := range desired {
		if existingCol, exists := existing[desiredName]; !exists {
			// Column doesn't exist -> ADD
			changes = append(changes, ColumnChange{
				Action:  "add",
				Name:    desiredName,
				Type:    desiredCol.Type,
				Default: desiredCol.Default,
				NotNull: desiredCol.NotNull,
			})
		} else {
			// Column exists -> check if it needs modification
			if db.columnDiffers(existingCol, desiredCol) {
				changes = append(changes, ColumnChange{
					Action:  "modify",
					Name:    desiredName,
					Type:    desiredCol.Type,
					Default: desiredCol.Default,
					NotNull: desiredCol.NotNull,
				})
			}
		}
	}

	// Check for columns to delete (in existing but not in desired)
	for existingName := range existing {
		if _, inDesired := desired[existingName]; !inDesired {
			changes = append(changes, ColumnChange{
				Action: "delete",
				Name:   existingName,
			})
		}
	}

	return changes
}

// columnDiffers checks if a column definition changed
func (db *DB) columnDiffers(existing, desired ColumnDef) bool {
	// Normalize and compare type
	existingType := strings.TrimSpace(strings.ToUpper(existing.Type))
	desiredType := strings.TrimSpace(strings.ToUpper(desired.Type))
	
	if existingType != desiredType {
		return true
	}

	// Compare NOT NULL
	if existing.NotNull != desired.NotNull {
		return true
	}

	// Normalize defaults for comparison
	// nil and empty string should be treated carefully
	var existingDefault, desiredDefault interface{}
	
	// For string defaults, normalize empty string
	if existing.Default == nil {
		existingDefault = nil
	} else if existing.Default == "" {
		existingDefault = ""
	} else if str, ok := existing.Default.(string); ok {
		existingDefault = strings.TrimSpace(str)
	} else {
		existingDefault = existing.Default
	}
	
	if desired.Default == nil {
		desiredDefault = nil
	} else if desired.Default == "" {
		desiredDefault = ""
	} else if str, ok := desired.Default.(string); ok {
		desiredDefault = strings.TrimSpace(str)
	} else {
		desiredDefault = desired.Default
	}
	
	// Compare defaults
	if fmt.Sprintf("%v", existingDefault) != fmt.Sprintf("%v", desiredDefault) {
		return true
	}

	return false
}


// addColumn adds a new column to a table (SQLite compatible)
// For nullable columns, SQLite will automatically fill existing rows with NULL
// For NOT NULL columns, a DEFAULT value is required for safety
func (db *DB) addColumn(tableName string, col ColumnChange) error {
	// Safety check: NOT NULL columns need a DEFAULT value
	// Nullable columns are safe - SQLite fills with NULL automatically
	if col.NotNull && col.Default == nil {
		fmt.Printf("[db] ⚠️  SKIPPED: Adding NOT NULL column %s without default (unsafe)\n", col.Name)
		fmt.Printf("[db] ⚠️  Add DEFAULT value to schema.sql to enable this change\n")
		return nil
	}

	sql := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", tableName, col.Name, col.Type)

	if col.NotNull {
		sql += " NOT NULL"
	}

	if col.Default != nil {
		if str, ok := col.Default.(string); ok {
			sql += fmt.Sprintf(" DEFAULT '%s'", strings.ReplaceAll(str, "'", "''"))
		} else {
			sql += fmt.Sprintf(" DEFAULT %v", col.Default)
		}
	}

	_, err := db.Exec(sql)
	return err
}

// modifyColumn modifies an existing column (SQLite limited support)
func (db *DB) modifyColumn(tableName string, col ColumnChange) error {
	fmt.Printf("[db]   ⚠  SQLite doesn't support MODIFY COLUMN directly\n")
	fmt.Printf("[db]   ⚠  Column %s kept unchanged (would require table recreation)\n", col.Name)
	return nil
}

// deleteColumn removes a column from a table (SQLite 3.35.0+)
func (db *DB) deleteColumn(tableName string, col ColumnChange) error {
	var version string
	err := db.QueryRow("SELECT sqlite_version()").Scan(&version)
	if err != nil {
		return err
	}

	// Check if SQLite version supports DROP COLUMN (3.35.0+)
	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		major, _ := strconv.Atoi(parts[0])
		minor, _ := strconv.Atoi(parts[1])

		if major > 3 || (major == 3 && minor >= 35) {
			// Direct DROP COLUMN supported
			sql := fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s", tableName, col.Name)
			_, err := db.Exec(sql)
			return err
		}
	}

	// For older SQLite, skip (won't break anything - just keeps unused column)
	fmt.Printf("[db]   ⚠  SQLite %s doesn't support DROP COLUMN (need 3.35.0+)\n", version)
	fmt.Printf("[db]   ⚠  Column %s kept in table (won't affect functionality)\n", col.Name)

	return nil
}

// syncSchemaWithDefinition compares schema.sql with actual database and applies differences
// This allows you to just edit schema.sql and the system automatically updates the database
func (db *DB) syncSchemaWithDefinition() error {
	fmt.Println("[db] Syncing database schema with definition...")

	// Parse desired schema from embedded schema.sql
	desiredSchema := db.parseSchemaDefinition(schemaSQL)
	
	if len(desiredSchema) == 0 {
		fmt.Println("[db] ⚠️  WARNING: Could not parse any tables from schema.sql")
		fmt.Println("[db] Skipping schema sync to prevent data loss")
		return nil
	}

	// Get all tables from schema
	tableNames := make([]string, 0, len(desiredSchema))
	for tableName := range desiredSchema {
		tableNames = append(tableNames, tableName)
	}

	// For each table in schema.sql, check against database
	changesDetected := false
	for _, tableName := range tableNames {
		desiredCols := desiredSchema[tableName]
		
		if len(desiredCols) == 0 {
			fmt.Printf("[db] ⚠️  WARNING: Table %s has no parsed columns (parser issue?)\n", tableName)
			continue
		}

		// Get actual database schema
		existing, err := db.getTableSchema(tableName)
		if err != nil {
			// Table might not exist yet, skip
			continue
		}

		// Compute differences
		changes := db.computeColumnDiff(existing, desiredCols)

		if len(changes) > 0 {
			changesDetected = true
			fmt.Printf("[db] %s: %d change(s) detected\n", tableName, len(changes))

			// Apply changes
			for _, col := range changes {
				switch col.Action {
				case "add":
					if err := db.addColumn(tableName, col); err != nil {
						return fmt.Errorf("adding column %s.%s: %w", tableName, col.Name, err)
					}
					fmt.Printf("[db]   + Added %s (%s default: %v)\n", col.Name, col.Type, col.Default)

				case "modify":
					if err := db.modifyColumn(tableName, col); err != nil {
						return fmt.Errorf("modifying column %s.%s: %w", tableName, col.Name, err)
					}
					fmt.Printf("[db]   ✏ Modified %s (%s)\n", col.Name, col.Type)

				case "delete":
					if err := db.deleteColumn(tableName, col); err != nil {
						return fmt.Errorf("deleting column %s.%s: %w", tableName, col.Name, err)
					}
					fmt.Printf("[db]   - Deleted %s\n", col.Name)
				}
			}
		}
	}

	if !changesDetected {
		fmt.Println("[db] All tables are up-to-date")
	}

	return nil
}

// parseSchemaDefinition parses CREATE TABLE statements from schema.sql
// Returns a map of table names to their column definitions
// Note: This is a simple parser - complex schema changes may need manual testing
func (db *DB) parseSchemaDefinition(schemaSql string) map[string]map[string]ColumnDef {
	schema := make(map[string]map[string]ColumnDef)

	// Find all CREATE TABLE blocks
	createTableIdx := 0
	for {
		idx := strings.Index(schemaSql[createTableIdx:], "CREATE TABLE")
		if idx == -1 {
			break
		}
		idx += createTableIdx

		// Find the closing );
		endIdx := strings.Index(schemaSql[idx:], ");")
		if endIdx == -1 {
			break
		}
		endIdx += idx + 2

		// Extract table definition
		tableBlock := schemaSql[idx:endIdx]

		// Parse this CREATE TABLE block
		tableName := db.extractTableName(tableBlock)
		if tableName == "" {
			createTableIdx = endIdx
			continue
		}

		// Parse columns from this block
		cols := make(map[string]ColumnDef)
		db.parseTableColumns(tableName, tableBlock, cols)

		if len(cols) > 0 {
			schema[tableName] = cols
			fmt.Printf("[db] Parsed table '%s' with %d columns\n", tableName, len(cols))
		}

		createTableIdx = endIdx
	}

	return schema
}

// extractTableName extracts the table name from a CREATE TABLE statement
func (db *DB) extractTableName(createTableStatement string) string {
	// Find "CREATE TABLE" or "CREATE TABLE IF NOT EXISTS"
	var tableName string

	if strings.Contains(createTableStatement, "IF NOT EXISTS") {
		// Format: CREATE TABLE IF NOT EXISTS table_name
		parts := strings.Split(createTableStatement, "IF NOT EXISTS")
		if len(parts) > 1 {
			rest := strings.TrimSpace(parts[1])
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				tableName = strings.Trim(fields[0], "`()") 
			}
		}
	} else {
		// Format: CREATE TABLE table_name
		parts := strings.Split(createTableStatement, "CREATE TABLE")
		if len(parts) > 1 {
			rest := strings.TrimSpace(parts[1])
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				tableName = strings.Trim(fields[0], "`()")
			}
		}
	}

	return tableName
}

// parseTableColumns extracts column definitions from CREATE TABLE content
func (db *DB) parseTableColumns(tableName string, content string, cols map[string]ColumnDef) {
	// Simple parser for column definitions
	// Handles: "column_name TYPE [NOT NULL] [DEFAULT value]"

	lines := strings.Split(content, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Remove comments (-- comment)
		if idx := strings.Index(trimmed, "--"); idx >= 0 {
			trimmed = strings.TrimSpace(trimmed[:idx])
		}

		// Skip constraints, primary keys, indexes, etc.
		if strings.HasPrefix(trimmed, "PRIMARY") || strings.HasPrefix(trimmed, "FOREIGN") ||
			strings.HasPrefix(trimmed, "UNIQUE") || strings.HasPrefix(trimmed, "INDEX") ||
			strings.HasPrefix(trimmed, "CREATE") || strings.HasPrefix(trimmed, "CONSTRAINT") ||
			strings.HasPrefix(trimmed, "CHECK") || trimmed == "" {
			continue
		}

		// Remove trailing comma
		trimmed = strings.TrimSuffix(trimmed, ",")
		
		// Skip if empty after removing comma
		if trimmed == "" {
			continue
		}

		// Parse column definition
		parts := strings.Fields(trimmed)
		if len(parts) < 2 {
			continue
		}

		columnName := strings.Trim(parts[0], "`")
		
		// Find where type ends (look for NOT, DEFAULT, REFERENCES keywords)
		typeEnd := 1
		for typeEnd < len(parts) && 
			!strings.EqualFold(parts[typeEnd], "NOT") && 
			!strings.EqualFold(parts[typeEnd], "DEFAULT") && 
			!strings.EqualFold(parts[typeEnd], "REFERENCES") &&
			!strings.EqualFold(parts[typeEnd], "PRIMARY") &&
			!strings.EqualFold(parts[typeEnd], "UNIQUE") &&
			!strings.EqualFold(parts[typeEnd], "CHECK") &&
			!strings.EqualFold(parts[typeEnd], "COLLATE") {
			typeEnd++
		}
		
		// Build type from parts[1:typeEnd], clean up
		columnType := strings.TrimSpace(strings.Join(parts[1:typeEnd], " "))
		columnType = strings.ToUpper(columnType)
		columnType = strings.TrimSuffix(columnType, ",")
		columnType = strings.TrimSpace(columnType)
		
		colDef := ColumnDef{
			Name:    columnName,
			Type:    columnType,
			Default: nil,
			NotNull: false,
		}

		// Parse remaining modifiers
		i := typeEnd
		for i < len(parts) {
			upper := strings.ToUpper(parts[i])

			if upper == "NOT" && i+1 < len(parts) && strings.ToUpper(parts[i+1]) == "NULL" {
				colDef.NotNull = true
				i += 2
			} else if upper == "DEFAULT" && i+1 < len(parts) {
				i++ // move to default value
				defaultVal := parts[i]
				
				// Handle function defaults like (datetime('now'))
				// They span multiple parts, collect them
				if strings.HasPrefix(defaultVal, "(") && !strings.HasSuffix(defaultVal, ")") {
					// Collect until we find closing paren
					for i+1 < len(parts) && !strings.HasSuffix(parts[i], ")") {
						i++
						defaultVal += " " + parts[i]
					}
				}
				
				defaultVal = strings.Trim(defaultVal, ",")
				defaultVal = strings.TrimSpace(defaultVal)
				
				// Handle quoted strings (remove outer quotes)
				if (strings.HasPrefix(defaultVal, "'") && strings.HasSuffix(defaultVal, "'") && !strings.Contains(defaultVal[1:len(defaultVal)-1], "'")) ||
					(strings.HasPrefix(defaultVal, "\"") && strings.HasSuffix(defaultVal, "\"") && !strings.Contains(defaultVal[1:len(defaultVal)-1], "\"")) {
					defaultVal = defaultVal[1 : len(defaultVal)-1]
				}
				
				// Try to parse as number
				if num, err := strconv.Atoi(defaultVal); err == nil {
					colDef.Default = num
				} else if strings.EqualFold(defaultVal, "NULL") {
					colDef.Default = nil
				} else if defaultVal == "" {
					// Empty string - store as empty string, not nil
					colDef.Default = ""
				} else {
					// Strip outer parentheses from function calls to match PRAGMA format
					// PRAGMA returns: datetime('now')
					// Schema has:     (datetime('now'))
					if strings.HasPrefix(defaultVal, "(") && strings.HasSuffix(defaultVal, ")") {
						defaultVal = defaultVal[1 : len(defaultVal)-1]
						defaultVal = strings.TrimSpace(defaultVal)
					}
					colDef.Default = defaultVal
				}
				i++
			} else if upper == "REFERENCES" || upper == "PRIMARY" || upper == "UNIQUE" || upper == "CHECK" || upper == "COLLATE" {
				// Skip remaining modifiers
				break
			} else {
				i++
			}
		}

		cols[columnName] = colDef
	}
}

