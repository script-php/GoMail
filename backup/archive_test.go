package backup

import (
	"archive/tar"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"gomail/config"
	"gomail/store"
)

func TestBackupTreeRejectsNonRegularSources(t *testing.T) {
	root := t.TempDir()
	realTree := filepath.Join(root, "real")
	if err := os.Mkdir(realTree, 0700); err != nil {
		t.Fatal(err)
	}
	linkedTree := filepath.Join(root, "linked")
	if err := os.Symlink(realTree, linkedTree); err != nil {
		t.Fatal(err)
	}
	var sources []sourceFile
	if err := appendTree(&sources, "acme", linkedTree); err == nil {
		t.Fatal("backup accepted a symlinked source root")
	}
	fifo := filepath.Join(realTree, "stuck-pipe")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if err := appendTree(&sources, "acme", realTree); err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("backup did not reject FIFO before opening it: %v", err)
	}
	if _, err := hashFile("tls/private-key.pem", fifo); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("backup hashing accepted a FIFO: %v", err)
	}
	regular := filepath.Join(root, "key.pem")
	if err := os.WriteFile(regular, []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	linkedFile := filepath.Join(root, "linked-key.pem")
	if err := os.Symlink(regular, linkedFile); err != nil {
		t.Fatal(err)
	}
	if record, err := hashFile("tls/private-key.pem", linkedFile); err != nil || record.Size != 3 {
		t.Fatalf("regular file reached through a symlink rejected: %+v, %v", record, err)
	}
}

func TestVerifyRejectsEntriesRestoreCannotExtract(t *testing.T) {
	for _, extra := range []*tar.Header{
		{Name: "attachments/link", Typeflag: tar.TypeSymlink, Linkname: "../outside"},
		{Name: "attachments/../outside", Typeflag: tar.TypeReg},
	} {
		t.Run(extra.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "archive.tar.gz")
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			gz := gzip.NewWriter(file)
			writer := tar.NewWriter(gz)
			counts := map[string]int64{}
			for _, table := range stagedCountTables {
				counts[table] = 0
			}
			manifest, _ := json.Marshal(Manifest{FormatVersion: FormatVersion, Database: "sqlite", Counts: counts, Files: []FileRecord{{Path: "config/config.json", Size: 0, SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}, {Path: "database/database.sqlite", Size: 0, SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}})
			if err := writer.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(manifest)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(manifest); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"config/config.json", "database/database.sqlite"} {
				if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0600, Typeflag: tar.TypeReg}); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.WriteHeader(extra); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := gz.Close(); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(path); err == nil {
				t.Fatal("verify accepted an entry restore would reject")
			}
		})
	}
}

func TestVerifyRejectsUnrestorableManifestCounts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		counts map[string]int64
	}{
		{"missing", map[string]int64{}},
		{"negative", map[string]int64{"domains": -1, "accounts": 0, "messages": 0, "attachments": 0, "outbound_queue": 0, "outbound_queue_events": 0}},
		{"unknown", map[string]int64{"domains": 0, "accounts": 0, "messages": 0, "attachments": 0, "outbound_queue": 0, "outbound_queue_events": 0, "other": 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "archive.tar.gz")
			if err := writeArchive(path, Manifest{FormatVersion: FormatVersion, Database: "sqlite", Counts: tc.counts}, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(path); err == nil || !strings.Contains(err.Error(), "count") {
				t.Fatalf("invalid counts not rejected: %v", err)
			}
		})
	}
}

func TestExtractRechecksVerifiedFileBytes(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	record, err := hashFile("attachments/file.bin", source)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{Files: []FileRecord{record}}
	if err := os.WriteFile(source, []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "changed.tar.gz")
	if err := writeArchive(archive, manifest, []sourceFile{{record.Path, source}}); err != nil {
		t.Fatal(err)
	}
	if err := extractArchive(archive, filepath.Join(root, "extracted"), manifest); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("changed archive bytes were not rejected during extraction: %v", err)
	}
}

func TestSQLiteRestoreRetainsPreRestoreSafetyArchive(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	cfg := &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test"}, TLS: config.TLSConfig{Mode: "none"}, Store: config.StoreConfig{Database: "sqlite", DBPath: filepath.Join(root, "mail.db"), AttachmentsPath: filepath.Join(root, "attachments")}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`{"server":{"hostname":"mail.example.test"},"tls":{"mode":"none"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenConfig(cfg.Store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateDomain(&store.Domain{Domain: "first.example", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	archive := filepath.Join(root, "backup", "original.tar.gz")
	if _, err := Create(cfg, configPath, archive, "test"); err != nil {
		t.Fatal(err)
	}
	db, err = store.OpenConfig(cfg.Store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateDomain(&store.Domain{Domain: "second.example", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := Restore(cfg, configPath, archive, true); err != nil {
		t.Fatal(err)
	}
	safetyPaths, err := filepath.Glob(filepath.Join(root, "gomail-pre-restore-*.tar.gz"))
	if err != nil || len(safetyPaths) != 1 {
		t.Fatalf("expected one retained safety archive, got %v: %v", safetyPaths, err)
	}
	safety, err := Verify(safetyPaths[0])
	if err != nil || safety.Counts["domains"] != 2 {
		t.Fatalf("safety archive did not preserve pre-restore domains: %+v, %v", safety.Counts, err)
	}
	db, err = store.OpenConfig(cfg.Store)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var restoredDomains int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM domains`).Scan(&restoredDomains); err != nil || restoredDomains != 1 {
		t.Fatalf("restored domain count = %d, %v", restoredDomains, err)
	}
}

func TestSQLiteRestoreClearsACMEFilesWhenArchiveTreeIsEmpty(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	cfg := &config.Config{
		Server: config.ServerConfig{Hostname: "mail.example.test"},
		TLS:    config.TLSConfig{Mode: "none", ACMEDir: filepath.Join(root, "acme")},
		Store:  config.StoreConfig{Database: "sqlite", DBPath: filepath.Join(root, "mail.db"), AttachmentsPath: filepath.Join(root, "attachments")},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	configBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.TLS.ACMEDir, 0700); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenConfig(cfg.Store)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "backup", "empty-acme.tar.gz")
	if _, err := Create(cfg, configPath, archive, "test"); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(cfg.TLS.ACMEDir, "old-account.key")
	if err := os.WriteFile(stale, []byte("stale credential"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(cfg, configPath, archive, true); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(cfg.TLS.ACMEDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("restored empty ACME tree contains stale files: %v, %v", entries, err)
	}
}

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
	if err := CheckRestoreJournal(configPath); err != nil {
		t.Fatalf("successful SQLite restore retained incomplete marker: %v", err)
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

func TestSQLiteBackupRejectsMissingAttachmentReference(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test"}, TLS: config.TLSConfig{Mode: "none"}, Store: config.StoreConfig{Database: "sqlite", DBPath: filepath.Join(root, "mail.db"), AttachmentsPath: filepath.Join(root, "attachments")}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"server":{"hostname":"mail.example.test"},"tls":{"mode":"none"}}`), 0600); err != nil {
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
	accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "a@example.test", PasswordHash: "x", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := db.GetFolderByType(accountID, "inbox")
	if err != nil || inbox == nil {
		t.Fatalf("inbox: %v %v", inbox, err)
	}
	messageID, err := db.SaveMessage(&store.Message{AccountID: accountID, FolderID: &inbox.ID, MessageID: "m1", Direction: "inbound"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveAttachment(&store.Attachment{MessageID: messageID, Filename: "missing.bin", Size: 4, StoragePath: "missing.bin"}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	archive := filepath.Join(root, "snapshot.tar.gz")
	if _, err := Create(cfg, configPath, archive, "test"); err == nil {
		t.Fatal("backup accepted a snapshot with a missing attachment file")
	}
	if err := CheckRestoreJournal(configPath); err != nil {
		t.Fatalf("backup preflight left a restore marker: %v", err)
	}
	if _, err := os.Stat(cfg.Store.DBPath); err != nil {
		t.Fatalf("live database changed after preflight rejection: %v", err)
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

func TestSQLiteRestoreCheckpointPreservesCommittedWALData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mail.db")
	live, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if _, err := live.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		t.Fatal(err)
	}
	if _, err := live.Exec(`CREATE TABLE mailbox (id INTEGER PRIMARY KEY, subject TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := live.Exec(`INSERT INTO mailbox (subject) VALUES ('committed only in WAL')`); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path + "-wal"); err != nil || info.Size() == 0 {
		t.Fatalf("expected live SQLite WAL before checkpoint: info=%v err=%v", info, err)
	}
	if err := checkpointSQLiteBeforeRestore(path); err != nil {
		t.Fatal(err)
	}
	// Simulate the restore removing sidecars, then failing before the staged
	// database is renamed into place. The original file must still be whole.
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	reopened, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var count int
	if err := reopened.QueryRow(`SELECT COUNT(*) FROM mailbox WHERE subject='committed only in WAL'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("failed replacement lost committed data: count=%d err=%v", count, err)
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

func TestStagedTreeSwitchRetainsPreviousGeneration(t *testing.T) {
	root := t.TempDir()
	live := filepath.Join(root, "attachments")
	source := filepath.Join(root, "source")
	for _, dir := range []string{live, source} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(live, "old.bin"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "new.bin"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	staged, err := stageRestoreTree(source, live)
	if err != nil {
		t.Fatal(err)
	}
	wantPrevious := restorePreviousTreePath(staged)
	previous, err := activateRestoreTreeRetained(staged, live)
	if err != nil {
		t.Fatal(err)
	}
	if previous != wantPrevious {
		t.Fatalf("previous tree path = %q, want %q", previous, wantPrevious)
	}
	for path, want := range map[string]string{filepath.Join(previous, "old.bin"): "old", filepath.Join(live, "new.bin"): "new"} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != want {
			t.Fatalf("retained tree file %s = %q, %v", path, data, err)
		}
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
