package store

import (
	"fmt"
	"regexp"
	"strings"
)

// Schemas are trusted embedded SQL, with one column/constraint per line and no
// semicolons in literals. Keep this deliberately small instead of rewriting SQL.
func schemaStatements(schema string) []string {
	var clean strings.Builder
	for _, line := range strings.Split(schema, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		clean.WriteString(line)
		clean.WriteByte('\n')
	}
	var statements []string
	for _, statement := range strings.Split(clean.String(), ";") {
		if statement = strings.TrimSpace(statement); statement != "" {
			statements = append(statements, statement)
		}
	}
	return statements
}

var mysqlTablePattern = regexp.MustCompile(`^CREATE TABLE IF NOT EXISTS ([a-z_]+) \(`)
var mysqlColumnPattern = regexp.MustCompile(`^([a-z_]+)\s+(.+)$`)
var mysqlIndexPattern = regexp.MustCompile(`^CREATE INDEX ([a-z_]+)\s+ON ([a-z_]+)\((.+)\)$`)
var mysqlUniquePattern = regexp.MustCompile(`^UNIQUE\(([^)]+)\)$`)
var mysqlForeignPattern = regexp.MustCompile(`^FOREIGN KEY \(([a-z_]+)\) REFERENCES ([a-z_]+)\(([a-z_]+)\) ON DELETE (CASCADE|SET NULL)$`)

// syncMySQLSchema creates missing objects and adds missing columns. Existing
// columns and data are never dropped or narrowed by automatic schema sync.
// Type changes and data transformations belong in RegisteredMigrations.
func (db *DB) syncMySQLSchema() error {
	statements := schemaStatements(mysqlSchemaSQL)
	for _, statement := range statements {
		match := mysqlTablePattern.FindStringSubmatch(statement)
		if match == nil {
			continue
		}
		table := match[1]
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("creating table %s: %w", table, err)
		}
		rows, err := db.Query(`SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?`, table)
		if err != nil {
			return err
		}
		existing := map[string]bool{}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			existing[name] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		lines := strings.Split(statement, "\n")
		for _, line := range lines[1:] {
			line = strings.TrimSuffix(strings.TrimSpace(line), ",")
			col := mysqlColumnPattern.FindStringSubmatch(line)
			if col == nil || existing[col[1]] {
				continue
			}
			if strings.Contains(col[2], "NOT NULL") && !strings.Contains(col[2], "DEFAULT") {
				var count int
				if err := db.QueryRow("SELECT COUNT(*) FROM " + quoteMySQL(table)).Scan(&count); err != nil {
					return err
				}
				if count > 0 {
					return fmt.Errorf("column %s.%s needs an explicit backfill migration before it can be NOT NULL", table, col[1])
				}
			}
			if _, err := db.Exec("ALTER TABLE " + quoteMySQL(table) + " ADD COLUMN " + quoteMySQL(col[1]) + " " + col[2]); err != nil {
				return fmt.Errorf("adding column %s.%s: %w", table, col[1], err)
			}
		}
	}
	// Indexes and constraints follow columns, including during upgrades.
	for _, statement := range statements {
		if index := mysqlIndexPattern.FindStringSubmatch(statement); index != nil {
			var count int
			if err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ?`, index[2], index[1]).Scan(&count); err != nil {
				return err
			}
			if count == 0 {
				if _, err := db.Exec(statement); err != nil {
					return fmt.Errorf("creating index %s: %w", index[1], err)
				}
			}
		}
		tableMatch := mysqlTablePattern.FindStringSubmatch(statement)
		if tableMatch == nil {
			continue
		}
		table := tableMatch[1]
		for _, line := range strings.Split(statement, "\n")[1:] {
			line = strings.TrimSuffix(strings.TrimSpace(line), ",")
			if unique := mysqlUniquePattern.FindStringSubmatch(line); unique != nil {
				columns := strings.ReplaceAll(unique[1], " ", "")
				var count int
				err := db.QueryRow(`SELECT COUNT(*) FROM (
     SELECT INDEX_NAME FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND NON_UNIQUE = 0
     GROUP BY INDEX_NAME HAVING GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX SEPARATOR ',') = ?
    ) AS matching_indexes`, table, columns).Scan(&count)
				if err != nil {
					return err
				}
				if count == 0 {
					if _, err := db.Exec("ALTER TABLE " + quoteMySQL(table) + " ADD " + line); err != nil {
						return fmt.Errorf("adding unique constraint to %s: %w", table, err)
					}
				}
			}
			if fk := mysqlForeignPattern.FindStringSubmatch(line); fk != nil {
				var count int
				err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?
     AND REFERENCED_TABLE_NAME = ? AND REFERENCED_COLUMN_NAME = ?`, table, fk[1], fk[2], fk[3]).Scan(&count)
				if err != nil {
					return err
				}
				if count == 0 {
					if _, err := db.Exec("ALTER TABLE " + quoteMySQL(table) + " ADD " + line); err != nil {
						return fmt.Errorf("adding foreign key to %s: %w", table, err)
					}
				}
			}
		}
	}
	return nil
}
