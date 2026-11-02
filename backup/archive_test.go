package backup

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"gomail/config"
	"gomail/store"
)

func TestBackupRefusesDiskPressure(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test"}, TLS: config.TLSConfig{Mode: "none"}, Store: config.StoreConfig{Database: "sqlite", DBPath: filepath.Join(root, "mail.db"), AttachmentsPath: filepath.Join(root, "attachments")}, StoragePressure: config.StoragePressureConfig{WarningFreeBytes: 1<<62 + 1, MinimumFreeBytes: 1 << 62}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"test":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenConfig(cfg.Store)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	_, err = CreateOnline(cfg, configPath, filepath.Join(root, "backup", "blocked.tar.gz"), "test")
	if !errors.Is(err, store.ErrDiskPressure) {
		t.Fatalf("backup was not blocked by disk pressure: %v", err)
	}
}

func TestSQLiteBackupVerifyAndRestoreRoundTrip(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	cfg := &config.Config{
		Server: config.ServerConfig{Hostname: "mail.example.test"},
		TLS:    config.TLSConfig{Mode: "none"},
		Store: config.StoreConfig{
			Database:        "sqlite",
			DBPath:          filepath.Join(root, "mail.db"),
			AttachmentsPath: filepath.Join(root, "attachments"),
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	configBytes := []byte(`{"server":{"hostname":"mail.example.test"},"tls":{"mode":"none"}}`)
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenConfig(cfg.Store)
	if err != nil {
		t.Fatal(err)
	}
	domainID, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "user@example.test", PasswordHash: "hash", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := os.WriteFile(filepath.Join(cfg.Store.AttachmentsPath, "attachment.bin"), []byte("attachment-data"), 0640); err != nil {
		t.Fatal(err)
	}

	archivePath := filepath.Join(root, "backups", "snapshot.tar.gz")
	manifest, err := Create(cfg, configPath, archivePath, "test")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Counts["accounts"] != 1 {
		t.Fatalf("account count=%d", manifest.Counts["accounts"])
	}
	if _, err := Verify(archivePath); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(cfg, configPath, archivePath, false); err == nil {
		t.Fatal("restore without force was accepted")
	}
	if err := os.WriteFile(configPath, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg.Store.DBPath); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(cfg.Store.AttachmentsPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(cfg, configPath, archivePath, true); err != nil {
		t.Fatal(err)
	}
	restoredConfig, _ := os.ReadFile(configPath)
	if string(restoredConfig) != string(configBytes) {
		t.Fatalf("config was not restored: %q", restoredConfig)
	}
	restoredAttachment, _ := os.ReadFile(filepath.Join(cfg.Store.AttachmentsPath, "attachment.bin"))
	if string(restoredAttachment) != "attachment-data" {
		t.Fatalf("attachment was not restored: %q", restoredAttachment)
	}
	db, err = store.OpenConfig(cfg.Store)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if count, err := db.CountAccounts(); err != nil || count != 1 {
		t.Fatalf("restored account count=%d err=%v", count, err)
	}
}

func TestRestoreRejectsMissingDatabaseBeforeTouchingSQLiteSidecars(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	if err := os.WriteFile(configPath, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	configRecord, err := hashFile("config/config.json", configPath)
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(root, "incomplete.tar.gz")
	manifest := Manifest{FormatVersion: FormatVersion, Database: "sqlite", Files: []FileRecord{configRecord}}
	if err := writeArchive(archivePath, manifest, []sourceFile{{"config/config.json", configPath}}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Store: config.StoreConfig{Database: "sqlite", DBPath: filepath.Join(root, "mail.db"), AttachmentsPath: filepath.Join(root, "attachments")}}
	walPath := cfg.Store.DBPath + "-wal"
	if err := os.WriteFile(walPath, []byte("live-wal"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(cfg, configPath, archivePath, true); err == nil {
		t.Fatal("incomplete backup was restored")
	}
	if data, err := os.ReadFile(walPath); err != nil || string(data) != "live-wal" {
		t.Fatalf("rejected restore changed WAL: %q %v", data, err)
	}
}

func TestInstanceLockPreventsConcurrentUse(t *testing.T) {
	cfg := &config.Config{Store: config.StoreConfig{Database: "sqlite", DBPath: filepath.Join(t.TempDir(), "mail.db")}}
	first, err := AcquireInstanceLock(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := AcquireInstanceLock(cfg); err == nil {
		t.Fatal("second instance lock was accepted")
	}
}

func TestOnlineBackupRunsWhileServerOwnsInstanceLock(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test"}, TLS: config.TLSConfig{Mode: "none"}, Store: config.StoreConfig{Database: "sqlite", DBPath: filepath.Join(root, "mail.db"), AttachmentsPath: filepath.Join(root, "attachments")}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"test":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenConfig(cfg.Store)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	lock, err := AcquireInstanceLock(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	archivePath := filepath.Join(root, "online.tar.gz")
	if _, err := CreateOnline(cfg, configPath, archivePath, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(archivePath); err != nil {
		t.Fatal(err)
	}
}

func TestReplaceTreeStagesBeforeReplacingLiveData(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "live")
	if err := os.MkdirAll(destination, 0750); err != nil {
		t.Fatal(err)
	}
	liveFile := filepath.Join(destination, "message.bin")
	if err := os.WriteFile(liveFile, []byte("live-data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := replaceTree(filepath.Join(root, "missing-source"), destination); err == nil {
		t.Fatal("missing restore source unexpectedly succeeded")
	}
	data, err := os.ReadFile(liveFile)
	if err != nil || string(data) != "live-data" {
		t.Fatalf("failed staged restore damaged live tree: %q %v", data, err)
	}
	source := filepath.Join(root, "source")
	if err := os.MkdirAll(source, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "restored.bin"), []byte("restored"), 0600); err != nil {
		t.Fatal(err)
	}
	staged, err := stageRestoreTree(source, destination)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(liveFile); err != nil || string(data) != "live-data" {
		t.Fatalf("staging changed the live tree: %q %v", data, err)
	}
	if err := activateRestoreTree(staged, destination); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(liveFile); !os.IsNotExist(err) {
		t.Fatalf("old tree survived successful replacement: %v", err)
	}
}

func TestStageRestoreFilePreservesLiveFileUntilActivation(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.json")
	destination := filepath.Join(root, "live.json")
	if err := os.WriteFile(source, []byte("restored"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("live"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := stageRestoreFile(filepath.Join(root, "missing"), destination, 0600); err == nil {
		t.Fatal("missing source unexpectedly staged")
	}
	staged, err := stageRestoreFile(source, destination, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(staged)
	if data, err := os.ReadFile(destination); err != nil || string(data) != "live" {
		t.Fatalf("staging changed live file: %q %v", data, err)
	}
	if err := activateRestoreFile(staged, destination); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(destination); err != nil || string(data) != "restored" {
		t.Fatalf("activation failed: %q %v", data, err)
	}
	if info, err := os.Stat(destination); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("restored mode = %v, error = %v", info, err)
	}
}

func TestStageRestoreFileRejectsDirectoryDestination(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("restored"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := stageRestoreFile(source, root, 0600); err == nil {
		t.Fatal("directory destination unexpectedly staged")
	}
}

func TestRestoreLayoutRejectsOverlappingDestinations(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{Store: config.StoreConfig{
		Database: "sqlite", DBPath: filepath.Join(root, "mail.db"),
		AttachmentsPath: filepath.Join(root, "attachments"),
	}, TLS: config.TLSConfig{Mode: "manual", CertFile: filepath.Join(root, "cert.pem"), KeyFile: filepath.Join(root, "key.pem")}}
	configPath := filepath.Join(root, "config.json")
	if err := validateRestoreLayout(cfg, configPath); err != nil {
		t.Fatalf("valid layout rejected: %v", err)
	}
	for _, change := range []struct {
		name string
		set  func()
	}{
		{"config inside attachments", func() { cfg.Store.AttachmentsPath = root }},
		{"database inside attachments", func() { cfg.Store.AttachmentsPath = filepath.Join(root, "mail.db", "attachments") }},
		{"duplicate TLS files", func() { cfg.TLS.KeyFile = cfg.TLS.CertFile }},
	} {
		t.Run(change.name, func(t *testing.T) {
			originalAttachments, originalKey := cfg.Store.AttachmentsPath, cfg.TLS.KeyFile
			defer func() { cfg.Store.AttachmentsPath, cfg.TLS.KeyFile = originalAttachments, originalKey }()
			change.set()
			if err := validateRestoreLayout(cfg, configPath); err == nil {
				t.Fatal("overlapping destinations accepted")
			}
		})
	}
}
