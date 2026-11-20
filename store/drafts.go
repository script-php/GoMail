package store

import (
	"database/sql"
	"fmt"
	"os"
	"time"
)

func (db *DB) SaveDraft(accountID, draftID int64, from, to, cc, subject, body string) (int64, error) {
	folder, err := db.GetFolderByType(accountID, "drafts")
	if err != nil || folder == nil {
		return 0, fmt.Errorf("drafts folder unavailable")
	}
	now := time.Now()
	newSize := int64(len(from) + len(to) + len(cc) + len(subject) + len(body))
	if draftID == 0 {
		draftID, err = db.SaveMessage(&Message{AccountID: accountID, FolderID: &folder.ID, MessageID: fmt.Sprintf("draft-%d", now.UnixNano()), Direction: "draft", MailFrom: from, FromAddr: from, ToAddr: to, CcAddr: cc, Subject: subject, TextBody: body, Size: newSize, IsRead: true, ReceivedAt: now})
	} else {
		tx, txErr := db.Begin()
		if txErr != nil {
			return 0, txErr
		}
		defer tx.Rollback()
		var oldSize int64
		if txErr = tx.QueryRow(`SELECT size FROM messages WHERE id=? AND account_id=? AND folder_id=? AND direction='draft' AND is_deleted=0`, draftID, accountID, folder.ID).Scan(&oldSize); txErr != nil {
			return 0, txErr
		}
		delta := newSize - oldSize
		if delta > 0 {
			if txErr = db.EnsureDiskSpace(delta); txErr != nil {
				return 0, txErr
			}
			txErr = reserveMailboxBytes(tx, accountID, delta)
		} else if delta < 0 {
			txErr = releaseMailboxBytes(tx, accountID, -delta)
		}
		if txErr != nil {
			return 0, txErr
		}
		result, execErr := tx.Exec(`UPDATE messages SET to_addr=?, cc_addr=?, subject=?, text_body=?, size=?, received_at=? WHERE id=? AND account_id=? AND folder_id=? AND direction='draft' AND is_deleted=0`, to, cc, subject, body, newSize, databaseTime(now), draftID, accountID, folder.ID)
		if execErr != nil {
			return 0, execErr
		}
		count, _ := result.RowsAffected()
		if count != 1 {
			return 0, sql.ErrNoRows
		}
		if txErr = db.touchIMAPMessageState(tx, draftID); txErr != nil {
			return 0, txErr
		}
		if txErr = tx.Commit(); txErr != nil {
			return 0, txErr
		}
		err = nil
	}
	if err == nil {
		db.NotifyIMAPChanges(accountID)
	}
	return draftID, err
}

func (db *DB) DeleteDraft(accountID, draftID int64) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var folderID, size int64
	var uid uint32
	if err := tx.QueryRow(`SELECT m.folder_id,m.size,s.uid FROM messages m JOIN imap_message_state s ON s.message_id=m.id
		WHERE m.id=? AND m.account_id=? AND m.direction='draft'`, draftID, accountID).Scan(&folderID, &size, &uid); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT storage_path FROM attachments WHERE message_id=?`, draftID)
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
	if _, err := db.recordIMAPExpunge(tx, folderID, uid); err != nil {
		return err
	}
	result, err := tx.Exec(`DELETE FROM messages WHERE id=? AND account_id=? AND direction='draft'`, draftID, accountID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return sql.ErrNoRows
	}
	if err := releaseMailboxBytes(tx, accountID, size); err != nil {
		return err
	}
	if err := updateAccountFolderCounts(tx, accountID); err != nil {
		return fmt.Errorf("updating draft folder counts: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	for _, path := range paths {
		if fullPath, ok := db.safeAttachmentPath(path); ok {
			_ = os.Remove(fullPath)
		}
	}
	db.NotifyIMAPChanges(accountID)
	return nil
}
