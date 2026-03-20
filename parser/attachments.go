package parser

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"gomail/store"
)

// SaveAttachments writes all parsed attachments to disk and returns Attachment model records.
func SaveAttachments(attachments []ParsedAttachment, messageDBID int64, basePath string) ([]*store.Attachment, error) {
	var records []*store.Attachment

	for i, att := range attachments {
		// Generate a safe, unique filename using hash
		hash := sha256.Sum256(att.Data)
		ext := filepath.Ext(att.Filename)
		if ext == "" {
			ext = ".bin"
		}
		safeFilename := fmt.Sprintf("%d_%d_%x%s", messageDBID, i, hash[:8], ext)
		storagePath := filepath.Join(safeFilename)
		fullPath := filepath.Join(basePath, safeFilename)

		// Write file
		if err := os.WriteFile(fullPath, att.Data, 0640); err != nil {
			return nil, fmt.Errorf("writing attachment %s: %w", att.Filename, err)
		}

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
