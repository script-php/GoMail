package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAttachmentFileRejectsSymlinkAndOverwrite(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "attachment")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteAttachmentFile(link, []byte("changed")); err == nil {
		t.Fatal("write followed symlink")
	}
	if _, err := ReadAttachmentFile(link); err == nil {
		t.Fatal("read followed symlink")
	}
	contents, err := os.ReadFile(outside)
	if err != nil || string(contents) != "original" {
		t.Fatalf("outside file changed: %q, %v", contents, err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := WriteAttachmentFile(link, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := WriteAttachmentFile(link, []byte("second")); err == nil {
		t.Fatal("existing attachment overwritten")
	}
	contents, err = ReadAttachmentFile(link)
	if err != nil || string(contents) != "first" {
		t.Fatalf("attachment changed: %q, %v", contents, err)
	}
}

func TestAttachmentFileDoesNotPublishAfterDirectorySyncFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "message.bin")
	previous := syncAttachmentDirectory
	t.Cleanup(func() { syncAttachmentDirectory = previous })
	calls := 0
	syncAttachmentDirectory = func(fd int) error {
		calls++
		if calls == 1 {
			return errors.New("simulated directory sync failure")
		}
		return previous(fd)
	}
	if err := WriteAttachmentFile(path, []byte("mail attachment")); err == nil {
		t.Fatal("attachment reported durable despite directory sync failure")
	}
	if calls != 2 {
		t.Fatalf("directory sync calls=%d, want creation and cleanup", calls)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed attachment write left a file: %v", err)
	}
}
