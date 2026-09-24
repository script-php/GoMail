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
	if draftID == 0 {
		draftID, err = db.SaveMessage(&Message{AccountID: accountID, FolderID: &folder.ID, MessageID: fmt.Sprintf("draft-%d", now.UnixNano()), Direction: "draft", MailFrom: from, FromAddr: from, ToAddr: to, CcAddr: cc, Subject: subject, TextBody: body, IsRead: true, ReceivedAt: now})
	} else {
		result, execErr := db.Exec(`UPDATE messages SET to_addr=?, cc_addr=?, subject=?, text_body=?, received_at=? WHERE id=? AND account_id=? AND direction='draft'`, to, cc, subject, body, databaseTime(now), draftID, accountID)
		if execErr != nil {
			return 0, execErr
		}
		count, _ := result.RowsAffected()
		if count != 1 {
			return 0, sql.ErrNoRows
		}
		err = nil
	}
	if err == nil {
		_ = db.UpdateFolderCounts(folder.ID)
	}
	return draftID, err
}

func (db *DB) DeleteDraft(accountID, draftID int64) error {
	var folderID int64
	if err := db.QueryRow(`SELECT folder_id FROM messages WHERE id=? AND account_id=? AND direction='draft'`, draftID, accountID).Scan(&folderID); err != nil {
		return err
	}
	attachments, err := db.GetAttachments(draftID)
	if err != nil {
		return err
	}
	result, err := db.Exec(`DELETE FROM messages WHERE id=? AND account_id=? AND direction='draft'`, draftID, accountID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return sql.ErrNoRows
	}
	for _, attachment := range attachments {
		if fullPath, ok := db.safeAttachmentPath(attachment.StoragePath); ok {
			_ = os.Remove(fullPath)
		}
	}
	return db.UpdateFolderCounts(folderID)
}
