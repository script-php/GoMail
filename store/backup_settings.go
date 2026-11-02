package store

import (
	"database/sql"
	"time"
)

type BackupSettings struct {
	Enabled        bool
	Directory      string
	IntervalHours  int
	RetentionCount int
	LastSuccessAt  *time.Time
	LastPath       string
	LastError      string
}

func (db *DB) GetBackupSettings(defaultDirectory string) (BackupSettings, error) {
	settings := BackupSettings{Directory: defaultDirectory, IntervalHours: 24, RetentionCount: 7}
	var enabled int
	var lastSuccess sql.NullTime
	err := db.QueryRow(`SELECT enabled, directory, interval_hours, retention_count, last_success_at, last_path, last_error FROM backup_settings WHERE id=1`).Scan(
		&enabled, &settings.Directory, &settings.IntervalHours, &settings.RetentionCount, &lastSuccess, &settings.LastPath, &settings.LastError)
	if err == sql.ErrNoRows {
		return settings, nil
	}
	if err != nil {
		return settings, err
	}
	settings.Enabled = enabled != 0
	if lastSuccess.Valid {
		value := lastSuccess.Time
		settings.LastSuccessAt = &value
	}
	return settings, nil
}

func (db *DB) SaveBackupSettings(settings BackupSettings) error {
	_, err := db.ExecuteUpsert(
		`INSERT INTO backup_settings (id, enabled, directory, interval_hours, retention_count, last_success_at, last_path, last_error) VALUES (1, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled, directory=excluded.directory, interval_hours=excluded.interval_hours, retention_count=excluded.retention_count, last_success_at=excluded.last_success_at, last_path=excluded.last_path, last_error=excluded.last_error`,
		`INSERT INTO backup_settings (id, enabled, directory, interval_hours, retention_count, last_success_at, last_path, last_error) VALUES (1, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE enabled=VALUES(enabled), directory=VALUES(directory), interval_hours=VALUES(interval_hours), retention_count=VALUES(retention_count), last_success_at=VALUES(last_success_at), last_path=VALUES(last_path), last_error=VALUES(last_error)`,
		boolToInt(settings.Enabled), settings.Directory, settings.IntervalHours, settings.RetentionCount, nullableTime(settings.LastSuccessAt), settings.LastPath, settings.LastError)
	return err
}

func (db *DB) RecordBackupResult(path string, completedAt time.Time, resultErr error) error {
	settings, err := db.GetBackupSettings("")
	if err != nil {
		return err
	}
	if resultErr != nil {
		settings.LastError = resultErr.Error()
	} else {
		settings.LastError = ""
		settings.LastPath = path
		settings.LastSuccessAt = &completedAt
	}
	return db.SaveBackupSettings(settings)
}

func nullableTime(value *time.Time) interface{} {
	if value == nil {
		return nil
	}
	return databaseTime(*value)
}
