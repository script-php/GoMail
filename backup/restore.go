package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gomail/config"
	_ "modernc.org/sqlite"
)

func Restore(cfg *config.Config, configPath, archivePath string, force bool) (Manifest, error) {
	return restore(cfg, configPath, archivePath, force, "")
}

// RestoreStaged imports a MySQL backup into an operator-provisioned empty
// database. The old database is retained; the config switch is the commit
// point, guarded by the incomplete-restore marker.
func RestoreStaged(cfg *config.Config, configPath, archivePath, stageDatabase string, force bool) (Manifest, error) {
	if cfg.Store.Database != "mysql" {
		return Manifest{}, fmt.Errorf("staged restore is supported only for MySQL")
	}
	if err := validateStagingDatabase(cfg.Store.MySQL.Name, stageDatabase); err != nil {
		return Manifest{}, err
	}
	return restore(cfg, configPath, archivePath, force, stageDatabase)
}

func restore(cfg *config.Config, configPath, archivePath string, force bool, stageDatabase string) (Manifest, error) {
	manifest, err := Verify(archivePath)
	if err != nil {
		return manifest, err
	}
	if !force {
		return manifest, fmt.Errorf("restore refused without explicit --force-restore")
	}
	if manifest.Database != cfg.Store.Database {
		return manifest, fmt.Errorf("backup database %q does not match configured database %q", manifest.Database, cfg.Store.Database)
	}
	if err := validateRestoreLayout(cfg, configPath); err != nil {
		return manifest, err
	}
	lock, err := AcquireInstanceLock(cfg)
	if err != nil {
		return manifest, err
	}
	defer lock.Close()
	if err := CheckRestoreJournal(configPath); err != nil {
		return manifest, err
	}
	if stageDatabase != "" {
		if err := checkEmptyStagingDatabase(cfg.Store.MySQL, stageDatabase); err != nil {
			return manifest, err
		}
	}

	work, err := os.MkdirTemp("", "gomail-restore-")
	if err != nil {
		return manifest, err
	}
	defer os.RemoveAll(work)
	if err := extractArchive(archivePath, work, manifest); err != nil {
		return manifest, err
	}
	if cfg.TLS.ACMEDir == "" {
		for _, record := range manifest.Files {
			if strings.HasPrefix(record.Path, "acme/") {
				return manifest, fmt.Errorf("backup contains ACME files but no destination ACME directory is configured")
			}
		}
	}
	// Tar archives contain files rather than empty directory entries. A valid
	// mailbox with no attachments therefore needs an explicit empty source tree.
	if err := os.MkdirAll(filepath.Join(work, "attachments"), 0750); err != nil {
		return manifest, err
	}
	// An empty ACME tree has no tar entries. Restore the empty generation too,
	// otherwise credentials left by the previous generation survive the restore.
	if cfg.TLS.ACMEDir != "" {
		if err := os.MkdirAll(filepath.Join(work, "acme"), 0750); err != nil {
			return manifest, err
		}
	}
	var safetyPath string
	// Either engine may have its database replaced before a later filesystem
	// activation fails. Preserve the complete old generation before any mutation.
	safetyPath = filepath.Join(filepath.Dir(configPath),
		fmt.Sprintf("gomail-pre-restore-%d.tar.gz", time.Now().UTC().UnixNano()))
	if _, err := CreateOnline(cfg, configPath, safetyPath, "pre-restore"); err != nil {
		return manifest, fmt.Errorf("refusing restore without a pre-restore safety archive: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Pre-restore safety archive retained at %s\n", safetyPath)
	// Stage every restored filesystem object before changing either database.
	// In particular, SQLite's old WAL/SHM files must remain intact if staging
	// the replacement snapshot fails.
	var stagedAttachments, stagedACME, stagedConfig, stagedCert, stagedKey, stagedDB string
	{
		stagedAttachments, err = stageRestoreTree(filepath.Join(work, "attachments"), cfg.Store.AttachmentsPath)
		if err != nil {
			return manifest, err
		}
		defer os.RemoveAll(stagedAttachments)
		if cfg.TLS.ACMEDir != "" {
			stagedACME, err = stageRestoreTree(filepath.Join(work, "acme"), cfg.TLS.ACMEDir)
			if err != nil {
				return manifest, err
			}
			defer os.RemoveAll(stagedACME)
		}
		stagedConfig, err = stageRestoreFile(filepath.Join(work, "config", "config.json"), configPath, 0600)
		if err != nil {
			return manifest, err
		}
		defer os.Remove(stagedConfig)
		if cfg.Store.Database == "mysql" {
			configTarget := *cfg
			configTarget.Store = cfg.Store
			configTarget.Store.MySQL = cfg.Store.MySQL
			if stageDatabase != "" {
				configTarget.Store.MySQL.Name = stageDatabase
			}
			if err := keepMySQLRestoreDestination(&configTarget, stagedConfig); err != nil {
				return manifest, err
			}
		}
		if cfg.TLS.Mode == "manual" {
			stagedCert, err = stageRestoreFileIfPresent(filepath.Join(work, "tls", "certificate.pem"), cfg.TLS.CertFile, 0600)
			if err != nil {
				return manifest, err
			}
			if stagedCert != "" {
				defer os.Remove(stagedCert)
			}
			stagedKey, err = stageRestoreFileIfPresent(filepath.Join(work, "tls", "private-key.pem"), cfg.TLS.KeyFile, 0600)
			if err != nil {
				return manifest, err
			}
			if stagedKey != "" {
				defer os.Remove(stagedKey)
			}
		}
		if cfg.Store.Database == "sqlite" {
			stagedDB, err = stageRestoreFile(filepath.Join(work, "database", "database.sqlite"), cfg.Store.DBPath, 0600)
			if err != nil {
				return manifest, err
			}
			defer os.Remove(stagedDB)
		}
	}
	if cfg.Store.Database == "sqlite" {
		snapshot, err := sql.Open("sqlite", stagedDB)
		if err != nil {
			return manifest, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		verifyErr := verifySQLiteStructure(ctx, snapshot, manifest.Counts)
		if verifyErr == nil {
			verifyErr = verifyStagedSnapshot(ctx, snapshot, manifest.Counts, stagedAttachments)
		}
		cancel()
		closeErr := snapshot.Close()
		if verifyErr != nil {
			return manifest, fmt.Errorf("invalid staged SQLite snapshot: %w", verifyErr)
		}
		if closeErr != nil {
			return manifest, closeErr
		}
	}

	// From this point onward, either database or filesystem state may change.
	// A crash or failed activation must not allow the service to reopen a
	// partially restored generation, regardless of database engine.
	if stageDatabase != "" {
		// The safety archive and file staging can take a long time; recheck
		// immediately before import to catch an accidentally reused database.
		if err := checkEmptyStagingDatabase(cfg.Store.MySQL, stageDatabase); err != nil {
			return manifest, err
		}
	}
	previousAttachments, previousACME := "", ""
	if stageDatabase != "" {
		previousAttachments = restorePreviousTreePath(stagedAttachments)
		if stagedACME != "" {
			previousACME = restorePreviousTreePath(stagedACME)
		}
	}
	stagedConfigRecord, err := hashFile("config/config.json", stagedConfig)
	if err != nil {
		return manifest, fmt.Errorf("hashing staged restore configuration: %w", err)
	}
	if err := beginRestoreJournal(configPath, archivePath, safetyPath, cfg.Store.MySQL.Name, stageDatabase, previousAttachments, previousACME, stagedConfigRecord.SHA256); err != nil {
		return manifest, err
	}
	if cfg.Store.Database == "mysql" {
		importTarget := *cfg
		importTarget.Store = cfg.Store
		importTarget.Store.MySQL = cfg.Store.MySQL
		if stageDatabase != "" {
			importTarget.Store.MySQL.Name = stageDatabase
		}
		if err := restoreMySQL(&importTarget, filepath.Join(work, "database", "database.sql")); err != nil {
			return manifest, err
		}
		// Check the imported generation before activating its attachments or
		// configuration. This matters for in-place restores too: a successful
		// mysql process exit alone does not establish that the expected rows and
		// attachment references survived the import.
		if err := verifyStagedMySQL(importTarget.Store.MySQL, manifest.Counts, stagedAttachments); err != nil {
			return manifest, fmt.Errorf("invalid restored MySQL snapshot: %w", err)
		}
		if err := updateRestoreJournalPhase(configPath, "database_imported"); err != nil {
			return manifest, err
		}
	} else {
		// A restored standalone snapshot must never be paired with WAL/SHM files
		// from the database it replaces.
		// Checkpoint first so a failed database rename cannot strand the old
		// database without committed transactions that existed only in its WAL.
		if err := checkpointSQLiteBeforeRestore(cfg.Store.DBPath); err != nil {
			return manifest, err
		}
		for _, suffix := range []string{"-wal", "-shm"} {
			if err := os.Remove(cfg.Store.DBPath + suffix); err != nil && !os.IsNotExist(err) {
				return manifest, err
			}
		}
		if err := activateRestoreFile(stagedDB, cfg.Store.DBPath); err != nil {
			return manifest, err
		}
		if err := updateRestoreJournalPhase(configPath, "database_activated"); err != nil {
			return manifest, err
		}
	}
	if stageDatabase != "" {
		_, err = activateRestoreTreeRetained(stagedAttachments, cfg.Store.AttachmentsPath)
	} else {
		err = activateRestoreTree(stagedAttachments, cfg.Store.AttachmentsPath)
	}
	if err != nil {
		return manifest, err
	}
	if err := updateRestoreJournalPhase(configPath, "attachments_activated"); err != nil {
		return manifest, err
	}
	if stagedACME != "" {
		if stageDatabase != "" {
			_, err = activateRestoreTreeRetained(stagedACME, cfg.TLS.ACMEDir)
		} else {
			err = activateRestoreTree(stagedACME, cfg.TLS.ACMEDir)
		}
		if err != nil {
			return manifest, err
		}
		if err := updateRestoreJournalPhase(configPath, "acme_activated"); err != nil {
			return manifest, err
		}
	}
	if cfg.TLS.Mode == "manual" {
		if stagedCert != "" {
			err = activateRestoreFile(stagedCert, cfg.TLS.CertFile)
		}
		if err != nil {
			return manifest, err
		}
		if stagedKey != "" {
			err = activateRestoreFile(stagedKey, cfg.TLS.KeyFile)
		}
		if err != nil {
			return manifest, err
		}
		if err := updateRestoreJournalPhase(configPath, "tls_activated"); err != nil {
			return manifest, err
		}
	}
	err = activateRestoreFile(stagedConfig, configPath)
	if err != nil {
		return manifest, err
	}
	if err := updateRestoreJournalPhase(configPath, "config_activated"); err != nil {
		return manifest, err
	}
	// The marker is the crash boundary. Do not clear it until the restored
	// filesystem generation and config switch are durable on disk.
	trees := []string{cfg.Store.AttachmentsPath}
	if stagedACME != "" {
		trees = append(trees, cfg.TLS.ACMEDir)
	}
	for _, path := range trees {
		if path != "" {
			if err := syncRestoredTree(path); err != nil {
				return manifest, fmt.Errorf("syncing restored tree %s: %w", path, err)
			}
		}
	}
	paths := append(trees, configPath)
	if cfg.Store.Database == "sqlite" {
		paths = append(paths, cfg.Store.DBPath)
	}
	if cfg.TLS.Mode == "manual" {
		paths = append(paths, cfg.TLS.CertFile, cfg.TLS.KeyFile)
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		if err := syncRestoreJournalDir(path); err != nil {
			return manifest, fmt.Errorf("syncing restored destination %s: %w", path, err)
		}
	}
	if err := updateRestoreJournalPhase(configPath, "durable"); err != nil {
		return manifest, err
	}
	if err := finishRestoreJournal(configPath); err != nil {
		return manifest, err
	}
	if stageDatabase != "" {
		fmt.Fprintf(os.Stderr, "Previous MySQL database %s retained; previous attachment tree: %s; previous ACME tree: %s\n", cfg.Store.MySQL.Name, previousAttachments, previousACME)
	}
	return manifest, nil
}

func checkpointSQLiteBeforeRestore(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("checking active SQLite database before restore: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("active SQLite database is not a regular file")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("opening active SQLite database before restore: %w", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var busy, logFrames, checkpointedFrames int
	if err := db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointedFrames); err != nil {
		return fmt.Errorf("checkpointing active SQLite database before restore: %w", err)
	}
	if busy != 0 {
		return fmt.Errorf("active SQLite WAL checkpoint is busy; refusing restore")
	}
	return nil
}

// A dump can be restored into a different MySQL database and attachment tree.
// Keep the selected destination's connection and filesystem paths in the
// installed config; otherwise the next start could reopen the archive source.
func keepMySQLRestoreDestination(cfg *config.Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("invalid archived configuration: %w", err)
	}
	if document == nil || len(document["tls"]) == 0 {
		return fmt.Errorf("archived configuration is missing TLS settings")
	}
	var archivedTLS config.TLSConfig
	if err := json.Unmarshal(document["tls"], &archivedTLS); err != nil {
		return fmt.Errorf("invalid archived TLS configuration: %w", err)
	}
	if archivedTLS.Mode != cfg.TLS.Mode {
		return fmt.Errorf("archived TLS mode %q differs from destination mode %q", archivedTLS.Mode, cfg.TLS.Mode)
	}
	storeData, err := json.Marshal(cfg.Store)
	if err != nil {
		return err
	}
	document["store"] = storeData
	var tlsFields map[string]json.RawMessage
	if err := json.Unmarshal(document["tls"], &tlsFields); err != nil {
		return err
	}
	if tlsFields == nil {
		return fmt.Errorf("archived TLS settings must be an object")
	}
	for field, value := range map[string]string{
		"acme_dir": cfg.TLS.ACMEDir, "cert_file": cfg.TLS.CertFile, "key_file": cfg.TLS.KeyFile,
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		tlsFields[field] = encoded
	}
	document["tls"], err = json.Marshal(tlsFields)
	if err != nil {
		return err
	}
	var dkimFields map[string]json.RawMessage
	if err := json.Unmarshal(document["dkim"], &dkimFields); err == nil && dkimFields != nil {
		encoded, err := json.Marshal(cfg.DKIM.KeysDir)
		if err != nil {
			return err
		}
		dkimFields["keys_dir"] = encoded
		document["dkim"], err = json.Marshal(dkimFields)
		if err != nil {
			return err
		}
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		return err
	}
	if _, err := config.Load(path); err != nil {
		return fmt.Errorf("invalid restored configuration for destination: %w", err)
	}
	return nil
}

// A tree activation renames its entire destination. Files inside another
// restored tree (or two destinations naming the same path) cannot be safely
// activated independently after a database import.
func validateRestoreLayout(cfg *config.Config, configPath string) error {
	type destination struct {
		name, path string
	}
	paths := []destination{{"config", configPath}, {"attachments", cfg.Store.AttachmentsPath}}
	if cfg.Store.Database == "sqlite" {
		paths = append(paths, destination{"database", cfg.Store.DBPath})
	}
	if cfg.TLS.ACMEDir != "" {
		paths = append(paths, destination{"ACME", cfg.TLS.ACMEDir})
	}
	if cfg.TLS.Mode == "manual" {
		paths = append(paths, destination{"TLS certificate", cfg.TLS.CertFile}, destination{"TLS key", cfg.TLS.KeyFile})
	}
	for i := range paths {
		if err := validateRestoreDestination(paths[i].path); err != nil {
			return fmt.Errorf("invalid %s restore destination: %w", paths[i].name, err)
		}
		absolute, err := filepath.Abs(paths[i].path)
		if err != nil {
			return err
		}
		paths[i].path = filepath.Clean(absolute)
		for j := 0; j < i; j++ {
			if restorePathsOverlap(paths[i].path, paths[j].path) {
				return fmt.Errorf("overlapping restore destinations: %s and %s", paths[j].name, paths[i].name)
			}
		}
	}
	return nil
}

func restorePathsOverlap(first, second string) bool {
	for _, pair := range [][2]string{{first, second}, {second, first}} {
		relative, err := filepath.Rel(pair[0], pair[1])
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func validateRestoreDestination(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("empty restore destination")
	}
	if filepath.Clean(path) == "." {
		return fmt.Errorf("refusing current-directory restore destination %q", path)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(absolute)
	root := volume + string(filepath.Separator)
	if filepath.Clean(absolute) == filepath.Clean(root) {
		return fmt.Errorf("refusing filesystem-root restore destination %q", path)
	}
	if workingDirectory, err := os.Getwd(); err == nil && filepath.Clean(absolute) == filepath.Clean(workingDirectory) {
		return fmt.Errorf("refusing working-directory restore destination %q", path)
	}
	return nil
}

func extractArchive(path, destination string, manifest Manifest) error {
	expected := make(map[string]FileRecord, len(manifest.Files))
	for _, record := range manifest.Files {
		expected[record.Path] = record
	}
	seen := make(map[string]bool, len(expected))
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			if len(seen) != len(expected) {
				return fmt.Errorf("archive changed after verification: missing files")
			}
			return nil
		}
		if err != nil {
			return err
		}
		if err := validateArchiveEntry(header); err != nil {
			return fmt.Errorf("archive changed after verification: %w", err)
		}
		clean := filepath.FromSlash(header.Name)
		if header.Name == "manifest.json" {
			continue
		}
		record, ok := expected[header.Name]
		if !ok || seen[header.Name] || header.Size != record.Size {
			return fmt.Errorf("archive changed after verification: unexpected file %q", header.Name)
		}
		seen[header.Name] = true
		target := filepath.Join(destination, clean)
		if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(header.Mode)&0770)
		if err != nil {
			return err
		}
		hash := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(output, hash), reader)
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if written != record.Size || hex.EncodeToString(hash.Sum(nil)) != record.SHA256 {
			return fmt.Errorf("archive changed after verification: checksum mismatch for %q", header.Name)
		}
	}
}

func replaceFileIfPresent(source, destination string, mode os.FileMode) error {
	if _, err := os.Stat(source); os.IsNotExist(err) {
		return nil
	}
	return replaceFile(source, destination, mode)
}

func replaceFile(source, destination string, mode os.FileMode) error {
	staged, err := stageRestoreFile(source, destination, mode)
	if err != nil {
		return err
	}
	defer os.Remove(staged)
	return activateRestoreFile(staged, destination)
}

func stageRestoreFileIfPresent(source, destination string, mode os.FileMode) (string, error) {
	if _, err := os.Stat(source); os.IsNotExist(err) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	return stageRestoreFile(source, destination, mode)
}

func stageRestoreFile(source, destination string, mode os.FileMode) (string, error) {
	if destination == "" {
		return "", fmt.Errorf("empty restore destination")
	}
	if info, err := os.Lstat(destination); err == nil && info.IsDir() {
		return "", fmt.Errorf("restore file destination %q is a directory", destination)
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0750); err != nil {
		return "", err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".gomail-restore-*.tmp")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	keepStaged := false
	defer func() {
		if !keepStaged {
			_ = os.Remove(temporaryPath)
		}
	}()
	if _, err := io.Copy(temporary, input); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(temporaryPath, mode); err != nil {
		return "", err
	}
	keepStaged = true
	return temporaryPath, nil
}

func activateRestoreFile(staged, destination string) error {
	return os.Rename(staged, destination)
}

func replaceTree(source, destination string) error {
	staged, err := stageRestoreTree(source, destination)
	if err != nil {
		return err
	}
	defer os.RemoveAll(staged)
	return activateRestoreTree(staged, destination)
}

func stageRestoreTree(source, destination string) (string, error) {
	if destination == "" {
		return "", fmt.Errorf("empty restore directory")
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0750); err != nil {
		return "", err
	}
	staged, err := os.MkdirTemp(parent, ".gomail-restore-tree-*")
	if err != nil {
		return "", err
	}
	if err := copyRestoreTree(source, staged); err != nil {
		_ = os.RemoveAll(staged)
		return "", err
	}
	return staged, nil
}

func activateRestoreTree(staged, destination string) error {
	old, err := activateRestoreTreeRetained(staged, destination)
	if err != nil {
		return err
	}
	if old != "" {
		if err := os.RemoveAll(old); err != nil {
			return fmt.Errorf("restored tree but could not remove previous tree %s: %w", old, err)
		}
	}
	return nil
}

func restorePreviousTreePath(staged string) string {
	return filepath.Join(filepath.Dir(staged), ".gomail-restore-old-"+filepath.Base(staged))
}

// Keep the previous directory so a staged MySQL restore retains the files
// corresponding to the database it leaves behind. The journal records this
// path before any rename; a crash therefore cannot silently erase recovery
// pointers.
func activateRestoreTreeRetained(staged, destination string) (string, error) {
	parent := filepath.Dir(destination)
	old := restorePreviousTreePath(staged)
	if err := os.Rename(destination, old); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	hadOld := false
	if _, err := os.Stat(old); err == nil {
		hadOld = true
	}
	if err := os.Rename(staged, destination); err != nil {
		if hadOld {
			_ = os.Rename(old, destination)
		}
		return "", err
	}
	if err := syncRestoreJournalDir(destination); err != nil {
		return "", fmt.Errorf("syncing restored tree switch in %s: %w", parent, err)
	}
	if hadOld {
		return old, nil
	}
	return "", nil
}

func copyRestoreTree(source, destination string) error {
	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == "." {
			return err
		}
		target := filepath.Join(destination, relative)
		if info.IsDir() {
			return os.MkdirAll(target, 0750)
		}
		return replaceFile(path, target, info.Mode()&0770)
	})
}

func restoreMySQL(cfg *config.Config, dumpPath string) error {
	input, err := os.Open(dumpPath)
	if err != nil {
		return err
	}
	defer input.Close()
	arguments := []string{"-h", cfg.Store.MySQL.Host, "-P", fmt.Sprint(cfg.Store.MySQL.Port), "-u", cfg.Store.MySQL.User, cfg.Store.MySQL.Name}
	arguments = append(mysqlClientTLSArgs(cfg.Store.MySQL), arguments...)
	command := exec.Command("mysql", arguments...)
	command.Env = append(os.Environ(), "MYSQL_PWD="+cfg.Store.MySQL.Password)
	command.Stdin = input
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("mysql restore failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
