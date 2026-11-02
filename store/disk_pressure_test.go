package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestDiskPressureStatusAndWriteRefusal(t *testing.T) {
	db := openIMAPTestDB(t)
	original := filesystemFreeBytes
	filesystemFreeBytes = func(string) (int64, error) { return 150, nil }
	t.Cleanup(func() { filesystemFreeBytes = original })
	db.ConfigureDiskPressure(200, 100, t.TempDir())
	status, err := db.DiskPressureStatus()
	if err != nil || !status.Warning || status.RefusingWrites || status.FreeBytes != 150 {
		t.Fatalf("warning status=%+v err=%v", status, err)
	}
	if err := db.EnsureDiskSpace(40); err != nil {
		t.Fatalf("safe write rejected: %v", err)
	}
	if err := db.EnsureDiskSpace(51); !errors.Is(err, ErrDiskPressure) {
		t.Fatalf("unsafe write error=%v", err)
	}
	inbox, _ := db.GetFolderByType(1, "inbox")
	if _, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "disk-full", Direction: "inbound", RawMessage: make([]byte, 51), ReceivedAt: time.Now()}); !errors.Is(err, ErrDiskPressure) {
		t.Fatalf("message write was not refused: %v", err)
	}
}

func TestDiskPressureDisabledPreservesWrites(t *testing.T) {
	db := openIMAPTestDB(t)
	db.ConfigureDiskPressure(0, 0, filepath.Dir(t.TempDir()))
	original := filesystemFreeBytes
	filesystemFreeBytes = func(string) (int64, error) { return 0, errors.New("must not be called") }
	t.Cleanup(func() { filesystemFreeBytes = original })
	if err := db.EnsureDiskSpace(1 << 30); err != nil {
		t.Fatalf("disabled guard rejected write: %v", err)
	}
}
