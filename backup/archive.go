package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gomail/config"
	"gomail/store"
)

const FormatVersion = 1

type FileRecord struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	FormatVersion int              `json:"format_version"`
	CreatedAt     time.Time        `json:"created_at"`
	GoMailVersion string           `json:"gomail_version"`
	Database      string           `json:"database"`
	Counts        map[string]int64 `json:"counts"`
	Files         []FileRecord     `json:"files"`
}

type sourceFile struct{ logical, physical string }

func Create(cfg *config.Config, configPath, outputPath, version string) (Manifest, error) {
	return create(cfg, configPath, outputPath, version, true)
}

// CreateOnline creates a verified snapshot while the server owns the instance
// lock. Immutable attachment files plus final archive verification make races
// fail closed; Create remains the preferred offline command.
func CreateOnline(cfg *config.Config, configPath, outputPath, version string) (Manifest, error) {
	return create(cfg, configPath, outputPath, version, false)
}

func create(cfg *config.Config, configPath, outputPath, version string, acquireLock bool) (Manifest, error) {
	manifest := Manifest{FormatVersion: FormatVersion, CreatedAt: time.Now().UTC(), GoMailVersion: version, Database: cfg.Store.Database}
	if samePath(outputPath, cfg.Store.DBPath) || samePath(outputPath, configPath) || pathWithin(outputPath, cfg.Store.AttachmentsPath) || pathWithin(outputPath, cfg.TLS.ACMEDir) {
		return manifest, fmt.Errorf("backup output must be outside the configured database, attachments, ACME and configuration paths")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0750); err != nil {
		return manifest, fmt.Errorf("creating backup directory: %w", err)
	}
	var lock *InstanceLock
	var err error
	if acquireLock {
		lock, err = AcquireInstanceLock(cfg)
		if err != nil {
			return manifest, err
		}
		defer lock.Close()
	}

	work, err := os.MkdirTemp("", "gomail-backup-")
	if err != nil {
		return manifest, err
	}
	defer os.RemoveAll(work)

	db, err := store.OpenConfig(cfg.Store)
	if err != nil {
		return manifest, err
	}
	databaseDirectory := filepath.Dir(cfg.Store.DBPath)
	if cfg.Store.Database == "mysql" {
		databaseDirectory = cfg.Store.AttachmentsPath
	}
	db.ConfigureDiskPressure(cfg.StoragePressure.WarningFreeBytes, cfg.StoragePressure.MinimumFreeBytes, databaseDirectory, cfg.Store.AttachmentsPath)
	estimatedBytes, err := estimateBackupBytes(cfg, configPath)
	if err != nil {
		db.Close()
		return manifest, err
	}
	if err := db.EnsureDiskSpaceAt(filepath.Dir(outputPath), estimatedBytes); err != nil {
		db.Close()
		return manifest, fmt.Errorf("backup blocked by disk pressure: %w", err)
	}
	if err := db.EnsureDiskSpaceAt(work, estimatedBytes); err != nil {
		db.Close()
		return manifest, fmt.Errorf("backup workspace blocked by disk pressure: %w", err)
	}
	manifest.Counts, err = db.BackupCounts()
	if err != nil {
		db.Close()
		return manifest, err
	}
	databaseFile := filepath.Join(work, "database")
	if cfg.Store.Database == "mysql" {
		databaseFile += ".sql"
		err = dumpMySQL(cfg, databaseFile)
	} else {
		databaseFile += ".sqlite"
		err = db.SnapshotSQLite(databaseFile)
	}
	db.Close()
	if err != nil {
		return manifest, err
	}

	sources := []sourceFile{{"database/" + filepath.Base(databaseFile), databaseFile}, {"config/config.json", configPath}}
	if err := appendTree(&sources, "attachments", cfg.Store.AttachmentsPath); err != nil {
		return manifest, err
	}
	if cfg.TLS.ACMEDir != "" {
		if err := appendTree(&sources, "acme", cfg.TLS.ACMEDir); err != nil {
			return manifest, err
		}
	}
	if cfg.TLS.Mode == "manual" {
		for logical, path := range map[string]string{"tls/certificate.pem": cfg.TLS.CertFile, "tls/private-key.pem": cfg.TLS.KeyFile} {
			if path != "" {
				sources = append(sources, sourceFile{logical, path})
			}
		}
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].logical < sources[j].logical })
	for _, source := range sources {
		record, err := hashFile(source.logical, source.physical)
		if err != nil {
			return manifest, err
		}
		manifest.Files = append(manifest.Files, record)
	}
	if err := writeArchive(outputPath, manifest, sources); err != nil {
		return manifest, err
	}
	if _, err := Verify(outputPath); err != nil {
		return manifest, fmt.Errorf("verifying completed backup: %w", err)
	}
	return manifest, nil
}

func estimateBackupBytes(cfg *config.Config, configPath string) (int64, error) {
	paths := []string{configPath, cfg.Store.AttachmentsPath}
	if cfg.Store.Database == "sqlite" {
		paths = append(paths, cfg.Store.DBPath)
	}
	if cfg.TLS.ACMEDir != "" {
		paths = append(paths, cfg.TLS.ACMEDir)
	}
	if cfg.TLS.Mode == "manual" {
		paths = append(paths, cfg.TLS.CertFile, cfg.TLS.KeyFile)
	}
	var total int64
	for _, path := range paths {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return 0, fmt.Errorf("estimating backup source %s: %w", path, err)
		}
		if !info.IsDir() {
			total += info.Size()
			continue
		}
		err = filepath.Walk(path, func(_ string, entry os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Mode().IsRegular() {
				total += entry.Size()
			}
			return nil
		})
		if err != nil {
			return 0, err
		}
	}
	// Allow for tar headers, the manifest and filesystem/accounting variance.
	return total + total/10 + 1<<20, nil
}

func samePath(left, right string) bool {
	if left == "" || right == "" {
		return false
	}
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil && leftAbs == rightAbs
}

func pathWithin(path, directory string) bool {
	if path == "" || directory == "" {
		return false
	}
	pathAbs, pathErr := filepath.Abs(path)
	directoryAbs, directoryErr := filepath.Abs(directory)
	if pathErr != nil || directoryErr != nil {
		return false
	}
	relative, err := filepath.Rel(directoryAbs, pathAbs)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func Verify(path string) (Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return Manifest{}, err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	actual := map[string]FileRecord{}
	var manifest Manifest
	manifestSeen := false
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return manifest, err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		hash := sha256.New()
		if header.Name == "manifest.json" {
			if manifestSeen {
				return manifest, fmt.Errorf("duplicate backup manifest")
			}
			manifestSeen = true
			if err := json.NewDecoder(io.TeeReader(reader, hash)).Decode(&manifest); err != nil {
				return manifest, err
			}
			continue
		}
		if _, duplicate := actual[header.Name]; duplicate {
			return manifest, fmt.Errorf("duplicate backup path %q", header.Name)
		}
		size, err := io.Copy(hash, reader)
		if err != nil {
			return manifest, err
		}
		actual[header.Name] = FileRecord{Path: header.Name, Size: size, SHA256: hex.EncodeToString(hash.Sum(nil))}
	}
	if !manifestSeen {
		return manifest, fmt.Errorf("missing backup manifest")
	}
	if manifest.FormatVersion != FormatVersion {
		return manifest, fmt.Errorf("unsupported backup format version %d", manifest.FormatVersion)
	}
	if len(actual) != len(manifest.Files) {
		return manifest, fmt.Errorf("manifest contains %d files but archive contains %d", len(manifest.Files), len(actual))
	}
	listed := make(map[string]struct{}, len(manifest.Files))
	for _, expected := range manifest.Files {
		if expected.Path == "manifest.json" {
			return manifest, fmt.Errorf("manifest cannot list itself")
		}
		if _, duplicate := listed[expected.Path]; duplicate {
			return manifest, fmt.Errorf("duplicate manifest path %q", expected.Path)
		}
		listed[expected.Path] = struct{}{}
		got, ok := actual[expected.Path]
		if !ok || got.Size != expected.Size || got.SHA256 != expected.SHA256 {
			return manifest, fmt.Errorf("checksum mismatch for %s", expected.Path)
		}
	}
	if _, ok := actual["config/config.json"]; !ok {
		return manifest, fmt.Errorf("backup is missing configuration")
	}
	var databasePath string
	switch manifest.Database {
	case "sqlite":
		databasePath = "database/database.sqlite"
	case "mysql":
		databasePath = "database/database.sql"
	default:
		return manifest, fmt.Errorf("unsupported backup database %q", manifest.Database)
	}
	if _, ok := actual[databasePath]; !ok {
		return manifest, fmt.Errorf("backup is missing database snapshot %q", databasePath)
	}
	return manifest, nil
}

func appendTree(sources *[]sourceFile, logicalRoot, physicalRoot string) error {
	info, err := os.Stat(physicalRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", physicalRoot)
	}
	return filepath.Walk(physicalRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in backup source: %s", path)
		}
		if info.Name() == ".gomail-instance.lock" {
			return nil
		}
		relative, err := filepath.Rel(physicalRoot, path)
		if err != nil {
			return err
		}
		*sources = append(*sources, sourceFile{filepath.ToSlash(filepath.Join(logicalRoot, relative)), path})
		return nil
	})
}

func hashFile(logical, physical string) (FileRecord, error) {
	file, err := os.Open(physical)
	if err != nil {
		return FileRecord{}, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return FileRecord{}, err
	}
	return FileRecord{Path: logical, Size: size, SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

func writeArchive(path string, manifest Manifest, sources []sourceFile) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("backup output already exists: %s", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".gomail-backup-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	gz := gzip.NewWriter(temporary)
	tarWriter := tar.NewWriter(gz)
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")
	if err := writeBytes(tarWriter, "manifest.json", manifestBytes, 0600); err != nil {
		return err
	}
	for _, source := range sources {
		if err := writeFile(tarWriter, source); err != nil {
			return err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temporaryPath, 0600); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func writeBytes(writer *tar.Writer, name string, data []byte, mode int64) error {
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data)), ModTime: time.Now()}); err != nil {
		return err
	}
	_, err := writer.Write(data)
	return err
}

func writeFile(writer *tar.Writer, source sourceFile) error {
	file, err := os.Open(source.physical)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	mode := int64(0600)
	if strings.HasPrefix(source.logical, "attachments/") {
		mode = 0640
	}
	if err := writer.WriteHeader(&tar.Header{Name: source.logical, Mode: mode, Size: info.Size(), ModTime: info.ModTime()}); err != nil {
		return err
	}
	_, err = io.Copy(writer, file)
	return err
}

func dumpMySQL(cfg *config.Config, destination string) error {
	arguments := []string{"--single-transaction", "--quick", "--skip-lock-tables", "-h", cfg.Store.MySQL.Host, "-P", fmt.Sprint(cfg.Store.MySQL.Port), "-u", cfg.Store.MySQL.User, cfg.Store.MySQL.Name}
	command := exec.Command("mysqldump", arguments...)
	command.Env = append(os.Environ(), "MYSQL_PWD="+cfg.Store.MySQL.Password)
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	command.Stdout = file
	command.Stderr = &stderr
	runErr := command.Run()
	closeErr := file.Close()
	if runErr != nil {
		return fmt.Errorf("mysqldump failed: %w: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	return closeErr
}
