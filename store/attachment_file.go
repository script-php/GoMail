package store

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// newAttachmentName avoids collisions with files left behind when a process
// crashes after writing a sidecar but before committing its message row.
func newAttachmentName(messageID int64, kind string, index int, data []byte, extension string) (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generating attachment filename: %w", err)
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%d_%s_%d_%x_%x%s", messageID, kind, index, digest[:8], nonce[:], extension), nil
}

var syncAttachmentDirectory = unix.Fsync

// WriteAttachmentFile creates a new attachment without following a pre-existing
// symlink or replacing an existing file. The contents and directory entry are
// durable before the caller commits a database reference to this path.
func WriteAttachmentFile(path string, data []byte) error {
	dir, name := filepath.Split(path)
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("invalid attachment filename")
	}
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)
	fd, err := unix.Openat(dirFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0640)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = syncAttachmentDirectory(dirFD)
	}
	if err != nil {
		_ = unix.Unlinkat(dirFD, name, 0)
		_ = syncAttachmentDirectory(dirFD)
	}
	return err
}

// ReadAttachmentFile rejects links when copying an attachment to another mailbox.
func ReadAttachmentFile(path string) ([]byte, error) {
	dir, name := filepath.Split(path)
	if name == "" || name == "." || name == ".." {
		return nil, fmt.Errorf("invalid attachment filename")
	}
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirFD)
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("attachment is not a regular file")
	}
	return io.ReadAll(file)
}
