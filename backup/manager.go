package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gomail/config"
	"gomail/logging"
	"gomail/store"
)

var ErrBackupInProgress = errors.New("backup already in progress")

// Retention owns only scheduler-generated archives, including the older
// second-resolution naming format. It must never remove restore safety copies
// or an operator's manually named archive in the same directory.
var managedBackupName = regexp.MustCompile(`^gomail-[0-9]{8}T[0-9]{6}(\.[0-9]{9})?Z\.tar\.gz$`)

type Manager struct {
	cfg        *config.Config
	db         *store.DB
	configPath string
	version    string
	runMu      sync.Mutex
	stop       chan struct{}
	done       chan struct{}
}

func NewManager(cfg *config.Config, db *store.DB, configPath, version string) *Manager {
	return &Manager{cfg: cfg, db: db, configPath: configPath, version: version, stop: make(chan struct{}), done: make(chan struct{})}
}

func (manager *Manager) ConfigPath() string { return manager.configPath }

func (manager *Manager) DefaultDirectory() string {
	if manager.cfg.Store.Database == "sqlite" {
		return filepath.Join(filepath.Dir(manager.cfg.Store.DBPath), "backups")
	}
	return filepath.Join(filepath.Dir(manager.cfg.Store.AttachmentsPath), "backups")
}

func (manager *Manager) Settings() (store.BackupSettings, error) {
	return manager.db.GetBackupSettings(manager.DefaultDirectory())
}

func (manager *Manager) SaveSettings(settings store.BackupSettings) error {
	settings.Directory = filepath.Clean(strings.TrimSpace(settings.Directory))
	if settings.Directory == "." || settings.Directory == "" {
		return fmt.Errorf("backup directory is required")
	}
	if settings.IntervalHours < 1 || settings.IntervalHours > 24*30 {
		return fmt.Errorf("backup interval must be between 1 and 720 hours")
	}
	if settings.RetentionCount < 1 || settings.RetentionCount > 365 {
		return fmt.Errorf("backup retention must be between 1 and 365 archives")
	}
	probe := filepath.Join(settings.Directory, "probe.tar.gz")
	if samePath(probe, manager.cfg.Store.DBPath) || pathWithin(probe, manager.cfg.Store.AttachmentsPath) || pathWithin(probe, manager.cfg.TLS.ACMEDir) {
		return fmt.Errorf("backup directory must be outside database, attachment and ACME state")
	}
	if err := os.MkdirAll(settings.Directory, 0750); err != nil {
		return err
	}
	if err := validateBackupDestination(manager.cfg, manager.configPath, probe); err != nil {
		return err
	}
	return manager.db.SaveBackupSettings(settings)
}

func (manager *Manager) RunNow() (Manifest, string, error) {
	return manager.runNowAt(time.Now().UTC())
}

func (manager *Manager) runNowAt(startedAt time.Time) (Manifest, string, error) {
	if !manager.runMu.TryLock() {
		return Manifest{}, "", ErrBackupInProgress
	}
	defer manager.runMu.Unlock()
	settings, err := manager.Settings()
	if err != nil {
		return Manifest{}, "", err
	}
	if err := manager.SaveSettings(settings); err != nil {
		return Manifest{}, "", err
	}
	filename := "gomail-" + startedAt.UTC().Format("20060102T150405.000000000Z") + ".tar.gz"
	path := filepath.Join(settings.Directory, filename)
	manifest, createErr := CreateOnline(manager.cfg, manager.configPath, path, manager.version)
	completedAt := time.Now().UTC()
	if err := manager.db.RecordBackupResult(path, completedAt, createErr); err != nil {
		logging.Error(fmt.Sprintf("[backup] could not record backup result for %s: %v", path, err))
	}
	if createErr != nil {
		return manifest, path, createErr
	}
	if err := manager.applyRetentionKeeping(settings.Directory, settings.RetentionCount, path); err != nil {
		logging.Warn(fmt.Sprintf("[backup] retention cleanup failed: %v", err))
	}
	return manifest, path, nil
}

func (manager *Manager) Start() {
	go func() {
		defer close(manager.done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		manager.runScheduled()
		for {
			select {
			case <-ticker.C:
				manager.runScheduled()
			case <-manager.stop:
				return
			}
		}
	}()
}

func (manager *Manager) Stop() {
	select {
	case <-manager.stop:
		return
	default:
		close(manager.stop)
		<-manager.done
	}
}

func (manager *Manager) runScheduled() {
	settings, err := manager.Settings()
	if err != nil {
		logging.Error(fmt.Sprintf("[backup] automatic backup settings unavailable: %v", err))
		return
	}
	if !settings.Enabled {
		return
	}
	now := time.Now().UTC()
	if settings.LastSuccessAt != nil && !settings.LastSuccessAt.After(now) && now.Sub(*settings.LastSuccessAt) < time.Duration(settings.IntervalHours)*time.Hour {
		return
	}
	if _, path, err := manager.RunNow(); err != nil {
		logging.Error(fmt.Sprintf("[backup] automatic backup failed: %v", err))
	} else {
		logging.Info(fmt.Sprintf("[backup] automatic backup completed: %s", path))
	}
}

func (manager *Manager) applyRetention(directory string, keep int) error {
	return manager.applyRetentionKeeping(directory, keep, "")
}

// A successful run must not remove the archive it just published, even when
// older archives have future-dated filenames because the host clock changed.
func (manager *Manager) applyRetentionKeeping(directory string, keep int, protected string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	var archives []string
	for _, entry := range entries {
		if entry.Type().IsRegular() && managedBackupName.MatchString(entry.Name()) {
			archives = append(archives, filepath.Join(directory, entry.Name()))
		}
	}
	sort.Strings(archives)
	for len(archives) > keep {
		candidate := 0
		if archives[candidate] == protected {
			candidate++
		}
		if candidate >= len(archives) {
			break
		}
		if err := os.Remove(archives[candidate]); err != nil {
			return err
		}
		archives = append(archives[:candidate], archives[candidate+1:]...)
	}
	return nil
}
