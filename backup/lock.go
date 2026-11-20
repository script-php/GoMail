package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"gomail/config"
)

type InstanceLock struct {
	files []*os.File
}

func LockPath(cfg *config.Config) string {
	if cfg.Store.Database == "mysql" {
		// Keep the lock outside the attachment tree: restore renames that tree.
		return filepath.Join(filepath.Dir(cfg.Store.AttachmentsPath),
			"."+filepath.Base(cfg.Store.AttachmentsPath)+".gomail-instance.lock")
	}
	return cfg.Store.DBPath + ".instance.lock"
}

func AcquireInstanceLock(cfg *config.Config) (*InstanceLock, error) {
	paths := []string{LockPath(cfg)}
	if cfg.Store.Database == "mysql" {
		// Also respect the original in-tree lock during upgrades while an
		// older GoMail process may still be running.
		paths = append(paths, filepath.Join(cfg.Store.AttachmentsPath, ".gomail-instance.lock"))
	}
	lock := &InstanceLock{}
	for _, path := range paths {
		file, err := acquireLockFile(path)
		if err != nil {
			_ = lock.Close()
			return nil, err
		}
		lock.files = append(lock.files, file)
	}
	return lock, nil
}

func acquireLockFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("another GoMail process is using this instance; stop the service first")
	}
	return file, nil
}

func (lock *InstanceLock) Close() error {
	if lock == nil {
		return nil
	}
	var firstErr error
	for _, file := range lock.files {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		if err := file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	lock.files = nil
	return firstErr
}
