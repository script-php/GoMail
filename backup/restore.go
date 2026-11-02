package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gomail/config"
)

func Restore(cfg *config.Config, configPath, archivePath string, force bool) (Manifest, error) {
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

	work, err := os.MkdirTemp("", "gomail-restore-")
	if err != nil {
		return manifest, err
	}
	defer os.RemoveAll(work)
	if err := extractArchive(archivePath, work); err != nil {
		return manifest, err
	}
	if cfg.Store.Database == "mysql" {
		// MySQL DDL in a dump is not transactional. Preserve the old state before
		// touching the configured database so an interrupted import is recoverable.
		safetyPath := filepath.Join(filepath.Dir(configPath),
			fmt.Sprintf("gomail-pre-restore-%d.tar.gz", time.Now().UTC().UnixNano()))
		if _, err := CreateOnline(cfg, configPath, safetyPath, "pre-restore"); err != nil {
			return manifest, fmt.Errorf("refusing MySQL restore without a pre-restore safety archive: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Pre-restore safety archive retained at %s\n", safetyPath)
	}
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
		if _, statErr := os.Stat(filepath.Join(work, "acme")); statErr == nil {
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

	if cfg.Store.Database == "mysql" {
		if err := restoreMySQL(cfg, filepath.Join(work, "database", "database.sql")); err != nil {
			return manifest, err
		}
	} else {
		// A restored standalone snapshot must never be paired with WAL/SHM files
		// from the database it replaces.
		for _, suffix := range []string{"-wal", "-shm"} {
			if err := os.Remove(cfg.Store.DBPath + suffix); err != nil && !os.IsNotExist(err) {
				return manifest, err
			}
		}
		if err := activateRestoreFile(stagedDB, cfg.Store.DBPath); err != nil {
			return manifest, err
		}
	}
	err = activateRestoreTree(stagedAttachments, cfg.Store.AttachmentsPath)
	if err != nil {
		return manifest, err
	}
	if _, err := os.Stat(filepath.Join(work, "acme")); err == nil {
		err = activateRestoreTree(stagedACME, cfg.TLS.ACMEDir)
		if err != nil {
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
	}
	err = activateRestoreFile(stagedConfig, configPath)
	if err != nil {
		return manifest, err
	}
	return manifest, nil
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

func extractArchive(path, destination string) error {
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
			return nil
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(filepath.FromSlash(header.Name))
		if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe archive path %q", header.Name)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		target := filepath.Join(destination, clean)
		if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(header.Mode)&0770)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, reader)
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
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
	parent := filepath.Dir(destination)
	old := filepath.Join(parent, ".gomail-restore-old-"+filepath.Base(staged))
	if err := os.Rename(destination, old); err != nil && !os.IsNotExist(err) {
		return err
	}
	hadOld := false
	if _, err := os.Stat(old); err == nil {
		hadOld = true
	}
	if err := os.Rename(staged, destination); err != nil {
		if hadOld {
			_ = os.Rename(old, destination)
		}
		return err
	}
	if hadOld {
		if err := os.RemoveAll(old); err != nil {
			return fmt.Errorf("restored tree but could not remove previous tree %s: %w", old, err)
		}
	}
	return nil
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
