package parser

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gomail/store"
)

// SaveAttachments writes all parsed attachments to disk and returns Attachment model records.
func SaveAttachments(attachments []ParsedAttachment, messageDBID int64, basePath string) ([]*store.Attachment, error) {
	var records []*store.Attachment
	var written []string
	cleanup := func() {
		for _, path := range written {
			_ = os.Remove(path)
		}
	}

	for i, att := range attachments {
		// A previous process may have written the sidecar but crashed before
		// committing its metadata. A fresh suffix lets the next repair succeed
		// without overwriting or trusting that orphaned file.
		hash := sha256.Sum256(att.Data)
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			cleanup()
			return nil, fmt.Errorf("generating attachment filename: %w", err)
		}
		ext := filepath.Ext(att.Filename)
		if !safeAttachmentExtension(ext) {
			ext = ".bin"
		}
		safeFilename := fmt.Sprintf("%d_%d_%x_%x%s", messageDBID, i, hash[:8], nonce[:], ext)
		storagePath := filepath.Join(safeFilename)
		fullPath := filepath.Join(basePath, safeFilename)

		// Write file
		if err := store.WriteAttachmentFile(fullPath, att.Data); err != nil {
			cleanup()
			return nil, fmt.Errorf("writing attachment %s: %w", att.Filename, err)
		}
		written = append(written, fullPath)

		records = append(records, &store.Attachment{
			MessageID:   messageDBID,
			Filename:    att.Filename,
			ContentType: att.ContentType,
			Size:        int64(len(att.Data)),
			StoragePath: storagePath,
		})
	}

	return records, nil
}

func safeAttachmentExtension(extension string) bool {
	if extension == "" || len(extension) > 16 || extension[0] != '.' {
		return false
	}
	for _, char := range extension[1:] {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return !strings.ContainsAny(extension, `/\\`)
}

// RemoveSavedAttachments compensates a failed metadata transaction. Paths are
// generated internally by SaveAttachments and contain no directory component.
func RemoveSavedAttachments(records []*store.Attachment, basePath string) {
	for _, record := range records {
		if record == nil || filepath.Base(record.StoragePath) != record.StoragePath {
			continue
		}
		_ = os.Remove(filepath.Join(basePath, record.StoragePath))
	}
}
