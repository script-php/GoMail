package parser

import (
	"fmt"
	"os"
	"path/filepath"

	"gomail/store"
)

// RepairAttachments reconstructs a missing sidecar from the authoritative raw
// MIME message. The caller must supply an account-scoped message. A write lock
// and metadata check prevent concurrent repairs from creating duplicate rows.
func RepairAttachments(db *store.DB, msg *store.Message, basePath string) error {
	if db == nil || msg == nil || msg.ID <= 0 || msg.AccountID <= 0 || !msg.HasAttachments {
		return fmt.Errorf("invalid attachment repair request")
	}
	parsed, err := Parse(msg.RawMessage)
	if err != nil {
		return fmt.Errorf("parsing preserved MIME: %w", err)
	}
	if len(parsed.Attachments) == 0 {
		return fmt.Errorf("preserved MIME has no extractable attachments")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// This no-op update obtains the message write lock on both SQLite and
	// InnoDB, while also checking ownership and the expected attachment flag.
	result, err := tx.Exec(`UPDATE messages SET has_attachments = has_attachments WHERE id = ? AND account_id = ? AND has_attachments = 1`, msg.ID, msg.AccountID)
	if err != nil {
		return err
	}
	matched, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if matched != 1 {
		return fmt.Errorf("message no longer available for repair")
	}
	rows, err := tx.Query(`SELECT storage_path, size FROM attachments WHERE message_id = ?`, msg.ID)
	if err != nil {
		return err
	}
	count := 0
	complete := true
	for rows.Next() {
		var name string
		var size int64
		if err := rows.Scan(&name, &size); err != nil {
			rows.Close()
			return err
		}
		count++
		if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
			complete = false
			continue
		}
		info, err := os.Lstat(filepath.Join(basePath, name))
		if err != nil || !info.Mode().IsRegular() || info.Size() != size {
			complete = false
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if complete && count == len(parsed.Attachments) {
		return nil
	}
	// Replace the incomplete metadata as a unit. The old sidecars are left
	// untouched; deleting paths from damaged metadata could remove files that
	// are still referenced elsewhere.
	if _, err := tx.Exec(`DELETE FROM attachments WHERE message_id = ?`, msg.ID); err != nil {
		return err
	}
	records, err := SaveAttachments(parsed.Attachments, msg.ID, basePath)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			RemoveSavedAttachments(records, basePath)
		}
	}()
	for _, attachment := range records {
		if _, err := tx.Exec(`INSERT INTO attachments (message_id, filename, content_type, size, storage_path) VALUES (?, ?, ?, ?, ?)`, attachment.MessageID, attachment.Filename, attachment.ContentType, attachment.Size, attachment.StoragePath); err != nil {
			return fmt.Errorf("saving repaired attachment metadata: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}
