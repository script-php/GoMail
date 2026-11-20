package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gomail/config"
	"gomail/store"
)

func TestBackupFilenameCollisionPreservesExistingArchive(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{
		Server: config.ServerConfig{Hostname: "mail.example.test"},
		TLS:    config.TLSConfig{Mode: "none"},
		Store:  config.StoreConfig{Database: "sqlite", DBPath: filepath.Join(root, "mail.db"), AttachmentsPath: filepath.Join(root, "attachments")},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"server":{"hostname":"mail.example.test"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenConfig(cfg.Store)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	manager := NewManager(cfg, db, configPath, "test")
	stamp := time.Date(2026, 11, 18, 10, 20, 30, 123456789, time.UTC)
	_, path, err := manager.runNowAt(stamp)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, secondPath, err := manager.runNowAt(stamp); err == nil || secondPath != path || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("colliding run path=%q err=%v", secondPath, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("existing archive changed or was removed: %v", err)
	}
	if _, err := Verify(path); err != nil {
		t.Fatalf("existing archive no longer verifies: %v", err)
	}
}

func TestBackupRetentionPreservesRestoreSafetyAndManualArchives(t *testing.T) {
	directory := t.TempDir()
	files := []string{
		"gomail-20261117T100000Z.tar.gz",
		"gomail-20261118T100000.123456789Z.tar.gz",
		"gomail-pre-restore-1795000000000000000.tar.gz",
		"gomail-operator-before-upgrade.tar.gz",
	}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	manager := &Manager{}
	if err := manager.applyRetention(directory, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, files[0])); !os.IsNotExist(err) {
		t.Fatalf("old managed archive was not removed: %v", err)
	}
	for _, name := range files[1:] {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Fatalf("retention removed %s: %v", name, err)
		}
	}
}

func TestBackupRetentionKeepsNewArchiveAfterClockMovesBackward(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{
		Server: config.ServerConfig{Hostname: "mail.example.test"},
		TLS:    config.TLSConfig{Mode: "none"},
		Store:  config.StoreConfig{Database: "sqlite", DBPath: filepath.Join(root, "mail.db"), AttachmentsPath: filepath.Join(root, "attachments")},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"server":{"hostname":"mail.example.test"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenConfig(cfg.Store)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	manager := NewManager(cfg, db, configPath, "test")
	settings, err := manager.Settings()
	if err != nil {
		t.Fatal(err)
	}
	settings.RetentionCount = 1
	if err := manager.SaveSettings(settings); err != nil {
		t.Fatal(err)
	}
	future := filepath.Join(settings.Directory, "gomail-20990101T000000.000000000Z.tar.gz")
	if err := os.WriteFile(future, []byte("old future-dated archive"), 0600); err != nil {
		t.Fatal(err)
	}
	_, current, err := manager.runNowAt(time.Date(2026, 11, 18, 10, 20, 30, 123456789, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(current); err != nil {
		t.Fatalf("new successful archive did not survive retention: %v", err)
	}
	if _, err := os.Stat(future); !os.IsNotExist(err) {
		t.Fatalf("future-dated older archive should be pruned: %v", err)
	}
}

func TestScheduledBackupRunsWhenSavedSuccessIsInFuture(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{
		Server: config.ServerConfig{Hostname: "mail.example.test"},
		TLS:    config.TLSConfig{Mode: "none"},
		Store:  config.StoreConfig{Database: "sqlite", DBPath: filepath.Join(root, "mail.db"), AttachmentsPath: filepath.Join(root, "attachments")},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"server":{"hostname":"mail.example.test"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenConfig(cfg.Store)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	manager := NewManager(cfg, db, configPath, "test")
	settings, err := manager.Settings()
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(365 * 24 * time.Hour)
	settings.Enabled = true
	settings.LastSuccessAt = &future
	settings.IntervalHours = 24
	if err := manager.SaveSettings(settings); err != nil {
		t.Fatal(err)
	}
	manager.runScheduled()
	updated, err := manager.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if updated.LastSuccessAt == nil || !updated.LastSuccessAt.Before(future) || updated.LastPath == "" {
		t.Fatalf("future success timestamp suppressed scheduled backup: %+v", updated)
	}
	if _, err := Verify(updated.LastPath); err != nil {
		t.Fatalf("scheduled archive does not verify: %v", err)
	}
}

func TestBackupRejectsSymlinkedDestinationInsideAttachments(t *testing.T) {
	root := t.TempDir()
	attachments := filepath.Join(root, "attachments")
	if err := os.MkdirAll(attachments, 0750); err != nil {
		t.Fatal(err)
	}
	linkedDirectory := filepath.Join(root, "backups-link")
	if err := os.Symlink(attachments, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Server: config.ServerConfig{Hostname: "mail.example.test"},
		TLS:    config.TLSConfig{Mode: "none"},
		Store:  config.StoreConfig{Database: "sqlite", DBPath: filepath.Join(root, "mail.db"), AttachmentsPath: attachments},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"server":{"hostname":"mail.example.test"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(linkedDirectory, "archive.tar.gz")
	if _, err := CreateOnline(cfg, configPath, output, "test"); err == nil {
		t.Fatal("created backup inside attachment tree through symlink")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("rejected backup left output behind: %v", err)
	}
	db, err := store.OpenConfig(cfg.Store)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	manager := NewManager(cfg, db, configPath, "test")
	settings, err := manager.Settings()
	if err != nil {
		t.Fatal(err)
	}
	settings.Directory = linkedDirectory
	if err := manager.SaveSettings(settings); err == nil {
		t.Fatal("saved backup directory linked inside attachments")
	}
}
