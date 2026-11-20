package backup

import (
	"os"
	"path/filepath"
	"testing"

	"gomail/config"
)

func TestMySQLInstanceLockSurvivesAttachmentTreeSwap(t *testing.T) {
	root := t.TempDir()
	attachments := filepath.Join(root, "attachments")
	cfg := &config.Config{Store: config.StoreConfig{Database: "mysql", AttachmentsPath: attachments}}
	lock, err := AcquireInstanceLock(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if got := LockPath(cfg); filepath.Dir(got) != root {
		t.Fatalf("lock remains inside swapped tree: %s", got)
	}
	if err := os.Rename(attachments, filepath.Join(root, "previous-attachments")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(attachments, 0750); err != nil {
		t.Fatal(err)
	}
	if second, err := AcquireInstanceLock(cfg); err == nil {
		second.Close()
		t.Fatal("second process acquired lock after attachment tree swap")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireInstanceLock(cfg)
	if err != nil {
		t.Fatalf("lock remained held after close: %v", err)
	}
	second.Close()
}

func TestMySQLInstanceLockRespectsLegacyHolder(t *testing.T) {
	root := t.TempDir()
	attachments := filepath.Join(root, "attachments")
	legacy := filepath.Join(attachments, ".gomail-instance.lock")
	if err := os.MkdirAll(attachments, 0750); err != nil {
		t.Fatal(err)
	}
	file, err := acquireLockFile(legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cfg := &config.Config{Store: config.StoreConfig{Database: "mysql", AttachmentsPath: attachments}}
	if lock, err := AcquireInstanceLock(cfg); err == nil {
		lock.Close()
		t.Fatal("new instance ignored older process lock")
	}
}
