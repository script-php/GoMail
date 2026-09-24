package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PermanentlyDeleteMessages removes account-owned messages that are already in
// Trash. Database deletion is atomic; attachment files are removed afterwards.
func (db *DB) PermanentlyDeleteMessages(accountID int64, ids []int64) error {
	if len(ids) == 0 || len(ids) > 500 {
		return fmt.Errorf("invalid message selection")
	}
	seen := make(map[int64]bool, len(ids))
	unique := ids[:0]
	for _, id := range ids {
		if id <= 0 || seen[id] {
			return fmt.Errorf("invalid or duplicate message ID")
		}
		seen[id] = true
		unique = append(unique, id)
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(unique)), ",")
	args := make([]interface{}, 0, len(unique)+1)
	args = append(args, accountID)
	for _, id := range unique {
		args = append(args, id)
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM messages WHERE account_id=? AND is_deleted=1 AND id IN (`+placeholders+`)`, args...).Scan(&count); err != nil {
		return err
	}
	if count != len(unique) {
		return sql.ErrNoRows
	}
	rows, err := tx.Query(`SELECT a.storage_path FROM attachments a JOIN messages m ON m.id=a.message_id
		WHERE m.account_id=? AND m.is_deleted=1 AND m.id IN (`+placeholders+`)`, args...)
	if err != nil {
		return err
	}
	var paths []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			rows.Close()
			return err
		}
		paths = append(paths, path)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM attachments WHERE message_id IN (`+placeholders+`)`, interfaceSlice(unique)...); err != nil {
		return err
	}
	result, err := tx.Exec(`DELETE FROM messages WHERE account_id=? AND is_deleted=1 AND id IN (`+placeholders+`)`, args...)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != int64(len(unique)) {
		return fmt.Errorf("deleted %d of %d messages", affected, len(unique))
	}
	if _, err := tx.Exec(`UPDATE folders SET
		total_count=(SELECT COUNT(*) FROM messages WHERE folder_id=folders.id AND is_deleted=(folders.folder_type='trash')),
		unread_count=(SELECT COUNT(*) FROM messages WHERE folder_id=folders.id AND is_read=0 AND is_deleted=(folders.folder_type='trash'))
		WHERE account_id=?`, accountID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	for _, path := range paths {
		if fullPath, ok := db.safeAttachmentPath(path); ok {
			_ = os.Remove(fullPath)
		}
	}
	return nil
}

func interfaceSlice(ids []int64) []interface{} {
	values := make([]interface{}, len(ids))
	for i, id := range ids {
		values[i] = id
	}
	return values
}

func (db *DB) safeAttachmentPath(storedPath string) (string, bool) {
	base, err := filepath.Abs(db.attachmentsPath)
	if err != nil || base == "" {
		return "", false
	}
	full, err := filepath.Abs(filepath.Join(base, filepath.Clean(storedPath)))
	if err != nil {
		return "", false
	}
	relative, err := filepath.Rel(base, full)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	return full, true
}
