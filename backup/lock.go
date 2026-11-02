package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"gomail/config"
)

type InstanceLock struct {
	file *os.File
}

func LockPath(cfg *config.Config) string {
	if cfg.Store.Database == "mysql" {
		return filepath.Join(cfg.Store.AttachmentsPath, ".gomail-instance.lock")
	}
	return cfg.Store.DBPath + ".instance.lock"
}

func AcquireInstanceLock(cfg *config.Config) (*InstanceLock, error) {
	path := LockPath(cfg)
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
	return &InstanceLock{file: file}, nil
}

func (lock *InstanceLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	_ = syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	return lock.file.Close()
}
