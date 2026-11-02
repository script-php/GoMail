package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestBackupSettingsRoundTrip(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "mail.db"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	defaults, err := db.GetBackupSettings("/default/backups")
	if err != nil || defaults.Directory != "/default/backups" || defaults.IntervalHours != 24 || defaults.RetentionCount != 7 {
		t.Fatalf("unexpected defaults: %+v err=%v", defaults, err)
	}
	settings := BackupSettings{Enabled: true, Directory: "/srv/backups", IntervalHours: 12, RetentionCount: 4}
	if err := db.SaveBackupSettings(settings); err != nil {
		t.Fatal(err)
	}
	completed := time.Now().UTC().Truncate(time.Second)
	if err := db.RecordBackupResult("/srv/backups/one.tar.gz", completed, nil); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetBackupSettings("")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.IntervalHours != 12 || got.RetentionCount != 4 || got.LastPath == "" || got.LastSuccessAt == nil || got.LastError != "" {
		t.Fatalf("unexpected persisted settings: %+v", got)
	}
}
