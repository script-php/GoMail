package store

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// WriteAttachmentFile creates a new attachment without following a pre-existing
// symlink or replacing an existing file.
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
		err = file.Close()
	} else {
		_ = file.Close()
	}
	if err != nil {
		_ = unix.Unlinkat(dirFD, name, 0)
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
