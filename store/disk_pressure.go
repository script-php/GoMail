package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"syscall"
)

var ErrDiskPressure = errors.New("insufficient free storage")

type DiskPressureStatus struct {
	FreeBytes      int64
	WarningFree    int64
	MinimumFree    int64
	Warning        bool
	RefusingWrites bool
	Path           string
}

var filesystemFreeBytes = func(path string) (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

func (db *DB) ConfigureDiskPressure(warningFree, minimumFree int64, paths ...string) {
	db.diskWarningFree = warningFree
	db.diskMinimumFree = minimumFree
	db.diskPaths = db.diskPaths[:0]
	seen := make(map[string]bool)
	for _, path := range paths {
		if path == "" {
			continue
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		if !seen[absolute] {
			seen[absolute] = true
			db.diskPaths = append(db.diskPaths, absolute)
		}
	}
}

func (db *DB) DiskPressureStatus() (DiskPressureStatus, error) {
	return db.diskPressureStatusAt("", 0)
}

func (db *DB) EnsureDiskSpace(requiredBytes int64) error {
	status, err := db.diskPressureStatusAt("", requiredBytes)
	if err != nil {
		return err
	}
	if status.RefusingWrites {
		return fmt.Errorf("%w: %s has %d bytes available; %d bytes must remain", ErrDiskPressure, status.Path, status.FreeBytes, status.MinimumFree)
	}
	return nil
}

func (db *DB) EnsureDiskSpaceAt(path string, requiredBytes int64) error {
	status, err := db.diskPressureStatusAt(path, requiredBytes)
	if err != nil {
		return err
	}
	if status.RefusingWrites {
		return fmt.Errorf("%w: %s has %d bytes available; %d bytes plus %d reserved bytes are required", ErrDiskPressure, status.Path, status.FreeBytes, requiredBytes, status.MinimumFree)
	}
	return nil
}

func (db *DB) diskPressureStatusAt(extraPath string, requiredBytes int64) (DiskPressureStatus, error) {
	status := DiskPressureStatus{FreeBytes: -1, WarningFree: db.diskWarningFree, MinimumFree: db.diskMinimumFree}
	if db.diskWarningFree == 0 && db.diskMinimumFree == 0 {
		return status, nil
	}
	paths := append([]string(nil), db.diskPaths...)
	if extraPath != "" {
		paths = append(paths, extraPath)
	}
	if len(paths) == 0 {
		return status, fmt.Errorf("disk-pressure paths are not configured")
	}
	for _, path := range paths {
		free, err := filesystemFreeBytes(path)
		if err != nil {
			return status, fmt.Errorf("checking free storage for %s: %w", path, err)
		}
		if status.FreeBytes < 0 || free < status.FreeBytes {
			status.FreeBytes, status.Path = free, path
		}
	}
	status.RefusingWrites = db.diskMinimumFree > 0 && (requiredBytes < 0 || status.FreeBytes-requiredBytes < db.diskMinimumFree)
	status.Warning = status.RefusingWrites || db.diskWarningFree > 0 && status.FreeBytes < db.diskWarningFree
	return status, nil
}
