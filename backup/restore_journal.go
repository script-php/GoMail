package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gomail/config"
	_ "modernc.org/sqlite"
)

// restoreJournalPath is deliberately outside the attachment tree: restoring
// that tree must not erase the evidence of an incomplete restore.
func restoreJournalPath(configPath string) string { return configPath + ".restore-incomplete" }

type restoreJournal struct {
	StartedAt            time.Time `json:"started_at"`
	UpdatedAt            time.Time `json:"updated_at,omitempty"`
	Phase                string    `json:"phase,omitempty"`
	Archive              string    `json:"archive"`
	SafetyArchive        string    `json:"safety_archive"`
	ActiveDatabase       string    `json:"active_database,omitempty"`
	StagingDatabase      string    `json:"staging_database,omitempty"`
	PreviousAttachments  string    `json:"previous_attachments,omitempty"`
	PreviousACME         string    `json:"previous_acme,omitempty"`
	ExpectedConfigSHA256 string    `json:"expected_config_sha256,omitempty"`
}

// CompleteDurableRestore clears only a marker whose final durability phase was
// recorded. Earlier phases may contain mixed generations and require an
// operator. The active generation is checked again before removing evidence.
func CompleteDurableRestore(configPath string) (bool, error) {
	data, err := os.ReadFile(restoreJournalPath(configPath))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var entry restoreJournal
	if err := json.Unmarshal(data, &entry); err != nil {
		return false, fmt.Errorf("decoding restore marker: %w", err)
	}
	if entry.Phase != "durable" {
		return false, nil
	}
	if entry.Archive == "" || entry.SafetyArchive == "" {
		return false, fmt.Errorf("durable restore marker lacks archive paths")
	}
	manifest, err := Verify(entry.Archive)
	if err != nil {
		return false, fmt.Errorf("verifying restored archive: %w", err)
	}
	safetyManifest, err := Verify(entry.SafetyArchive)
	if err != nil {
		return false, fmt.Errorf("verifying pre-restore safety archive: %w", err)
	}
	if safetyManifest.Database != manifest.Database {
		return false, fmt.Errorf("pre-restore safety archive database type differs from restored archive")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return false, fmt.Errorf("loading restored configuration: %w", err)
	}
	if cfg.Store.Database != manifest.Database {
		return false, fmt.Errorf("restored database type differs from archive")
	}
	if entry.ExpectedConfigSHA256 != "" {
		actual, err := hashFile("config/config.json", configPath)
		if err != nil {
			return false, fmt.Errorf("verifying restored configuration: %w", err)
		}
		if actual.SHA256 != entry.ExpectedConfigSHA256 {
			return false, fmt.Errorf("restored configuration differs from staged configuration")
		}
	}
	if cfg.Store.Database == "mysql" {
		if entry.ActiveDatabase == "" || (entry.StagingDatabase != "" && (cfg.Store.MySQL.Name != entry.StagingDatabase || entry.StagingDatabase == entry.ActiveDatabase)) || (entry.StagingDatabase == "" && cfg.Store.MySQL.Name != entry.ActiveDatabase) {
			return false, fmt.Errorf("restored MySQL database does not match restore marker")
		}
	}
	lock, err := AcquireInstanceLock(cfg)
	if err != nil {
		return false, err
	}
	defer lock.Close()
	if cfg.Store.Database == "mysql" {
		err = verifyStagedMySQL(cfg.Store.MySQL, manifest.Counts, cfg.Store.AttachmentsPath)
	} else {
		if _, statErr := os.Stat(cfg.Store.DBPath); statErr != nil {
			return false, fmt.Errorf("checking restored SQLite database: %w", statErr)
		}
		var db *sql.DB
		db, err = sql.Open("sqlite", cfg.Store.DBPath)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			err = verifySQLiteStructure(ctx, db, manifest.Counts)
			if err == nil {
				err = verifyStagedSnapshot(ctx, db, manifest.Counts, cfg.Store.AttachmentsPath)
			}
			cancel()
			if closeErr := db.Close(); err == nil {
				err = closeErr
			}
		}
	}
	if err != nil {
		return false, fmt.Errorf("verifying durable restore before startup: %w", err)
	}
	for _, record := range manifest.Files {
		physical := ""
		switch {
		case len(record.Path) > len("attachments/") && record.Path[:len("attachments/")] == "attachments/":
			name := record.Path[len("attachments/"):]
			if name != filepath.Base(name) || !filepath.IsLocal(name) {
				return false, fmt.Errorf("unsafe archive attachment path %q", record.Path)
			}
			physical = filepath.Join(cfg.Store.AttachmentsPath, name)
		case len(record.Path) > len("acme/") && record.Path[:len("acme/")] == "acme/":
			name := filepath.FromSlash(record.Path[len("acme/"):])
			if cfg.TLS.ACMEDir == "" || !filepath.IsLocal(name) {
				return false, fmt.Errorf("unsafe restored ACME path %q", record.Path)
			}
			if err := verifyRestoredParentDirectories(cfg.TLS.ACMEDir, name); err != nil {
				return false, fmt.Errorf("verifying restored ACME path %q: %w", record.Path, err)
			}
			physical = filepath.Join(cfg.TLS.ACMEDir, name)
		case record.Path == "tls/certificate.pem":
			physical = cfg.TLS.CertFile
		case record.Path == "tls/private-key.pem":
			physical = cfg.TLS.KeyFile
		case record.Path == "config/config.json" && cfg.Store.Database == "sqlite":
			physical = configPath // MySQL intentionally rewrites destination paths.
		}
		if physical == "" && (record.Path == "tls/certificate.pem" || record.Path == "tls/private-key.pem") {
			return false, fmt.Errorf("restored %s has no configured destination", record.Path)
		}
		if physical == "" {
			continue
		}
		info, err := os.Lstat(physical)
		if err != nil || !info.Mode().IsRegular() {
			return false, fmt.Errorf("restored %s is missing or not a regular file", record.Path)
		}
		actual, err := hashFile(record.Path, physical)
		if err != nil {
			return false, fmt.Errorf("verifying restored %s: %w", record.Path, err)
		}
		if actual.Size != record.Size || actual.SHA256 != record.SHA256 {
			return false, fmt.Errorf("restored %s differs from archive", record.Path)
		}
	}
	if err := verifyRestoredACMETree(cfg.TLS.ACMEDir, manifest.Files); err != nil {
		return false, fmt.Errorf("verifying restored ACME tree: %w", err)
	}
	if err := finishRestoreJournal(configPath); err != nil {
		return false, err
	}
	return true, nil
}

// A credential that is absent from the archive must not survive in the active
// ACME tree. Checking only the archived files would miss an old account key or
// certificate left behind by an incomplete directory switch.
func verifyRestoredACMETree(root string, files []FileRecord) error {
	if root == "" {
		return nil
	}
	expected := make(map[string]bool)
	for _, record := range files {
		if strings.HasPrefix(record.Path, "acme/") {
			expected[record.Path] = true
		}
	}
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		logical := "acme/" + filepath.ToSlash(relative)
		if !entry.Type().IsRegular() || !expected[logical] {
			return fmt.Errorf("unexpected file or symlink %s", logical)
		}
		return nil
	})
}

func verifyRestoredParentDirectories(root, name string) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("ACME root is missing or not a directory")
	}
	parent := filepath.Dir(name)
	if parent == "." {
		return nil
	}
	current := root
	for _, component := range strings.Split(parent, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("ACME parent is missing, not a directory, or a symlink")
		}
	}
	return nil
}

// CheckRestoreJournal refuses to start or repeat a restore until an operator
// has reconciled a potentially mixed database/filesystem generation.
func CheckRestoreJournal(configPath string) error {
	path := restoreJournalPath(configPath)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("checking restore marker %s: %w", path, err)
	}
	phase := "unknown"
	if data, err := os.ReadFile(path); err == nil {
		var entry restoreJournal
		if json.Unmarshal(data, &entry) == nil && entry.Phase != "" {
			phase = entry.Phase
		}
	}
	return fmt.Errorf("incomplete restore marker at %s (last recorded phase: %s); keep GoMail stopped, inspect the archive paths in the marker, recover and verify database and files, then remove the marker", path, phase)
}

func beginRestoreJournal(configPath, archivePath, safetyPath string, databaseNames ...string) error {
	if err := CheckRestoreJournal(configPath); err != nil {
		return err
	}
	var err error
	archivePath, err = filepath.Abs(archivePath)
	if err != nil {
		return err
	}
	safetyPath, err = filepath.Abs(safetyPath)
	if err != nil {
		return err
	}
	path := restoreJournalPath(configPath)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("creating restore marker: %w", err)
	}
	entry := restoreJournal{StartedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), Phase: "prepared", Archive: archivePath, SafetyArchive: safetyPath}
	if len(databaseNames) >= 2 {
		entry.ActiveDatabase, entry.StagingDatabase = databaseNames[0], databaseNames[1]
	}
	if len(databaseNames) >= 4 {
		entry.PreviousAttachments, entry.PreviousACME = databaseNames[2], databaseNames[3]
	}
	if len(databaseNames) >= 5 {
		entry.ExpectedConfigSHA256 = databaseNames[4]
	}
	encoded, err := json.MarshalIndent(entry, "", "  ")
	if err == nil {
		_, err = file.Write(append(encoded, '\n'))
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("writing restore marker %s: %w", path, err)
	}
	return syncRestoreJournalDir(path)
}

// The phase is the last durably recorded completed step, not proof that the
// next step did not start. Recovery must inspect both generations before
// removing the marker or switching configuration.
func updateRestoreJournalPhase(configPath, phase string) error {
	path := restoreJournalPath(configPath)
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading restore marker: %w", err)
	}
	var entry restoreJournal
	if err := json.Unmarshal(data, &entry); err != nil {
		return fmt.Errorf("decoding restore marker: %w", err)
	}
	entry.Phase, entry.UpdatedAt = phase, time.Now().UTC()
	encoded, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".gomail-restore-marker-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(append(encoded, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncRestoreJournalDir(path)
}

func finishRestoreJournal(configPath string) error {
	path := restoreJournalPath(configPath)
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("removing restore marker %s: %w", path, err)
	}
	return syncRestoreJournalDir(path)
}

func syncRestoreJournalDir(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func syncRestoredTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		directory, err := os.Open(path)
		if err != nil {
			return err
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	})
}
