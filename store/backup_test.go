package store

import (
	"regexp"
	"testing"
)

func TestBackupTableListMatchesSchemas(t *testing.T) {
	pattern := regexp.MustCompile(`(?m)^CREATE TABLE IF NOT EXISTS ([a-z_]+)\s*\(`)
	listed := make(map[string]bool)
	for _, table := range BackupTables() {
		if listed[table] {
			t.Fatalf("duplicate backup table %q", table)
		}
		listed[table] = true
	}
	for _, schema := range []struct{ name, text string }{{"sqlite", schemaSQL}, {"mysql", mysqlSchemaSQL}} {
		found := make(map[string]bool)
		for _, match := range pattern.FindAllStringSubmatch(schema.text, -1) {
			found[match[1]] = true
			if !listed[match[1]] {
				t.Errorf("%s schema table %q is absent from backup counts", schema.name, match[1])
			}
		}
		for table := range listed {
			if !found[table] {
				t.Errorf("backup table %q is absent from %s schema", table, schema.name)
			}
		}
	}
}
