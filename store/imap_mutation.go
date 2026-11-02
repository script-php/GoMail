package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type IMAPUIDPair struct {
	Source      uint32
	Destination uint32
}

func (db *DB) CopyIMAPMessages(accountID, sourceFolderID, destinationFolderID int64, messageIDs []int64) (pairs []IMAPUIDPair, err error) {
	if len(messageIDs) == 0 || len(messageIDs) > 500 {
		return nil, fmt.Errorf("invalid IMAP copy selection")
	}
	var sources []*Message
	var sourceAttachments [][]*Attachment
	for _, id := range messageIDs {
		message, getErr := db.GetMessage(id, accountID)
		if getErr != nil || message == nil || message.FolderID == nil || *message.FolderID != sourceFolderID {
			return nil, sql.ErrNoRows
		}
		attachments, getErr := db.GetAttachments(id)
		if getErr != nil {
			return nil, getErr
		}
		sources = append(sources, message)
		sourceAttachments = append(sourceAttachments, attachments)
	}
	var required int64
	for index, source := range sources {
		required += source.Size
		for _, attachment := range sourceAttachments[index] {
			required += attachment.Size
		}
	}
	if err := db.EnsureDiskSpace(required); err != nil {
		return nil, err
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var destinationType string
	if err = tx.QueryRow(`SELECT folder_type FROM folders WHERE id = ? AND account_id = ?`, destinationFolderID, accountID).Scan(&destinationType); err != nil {
		return nil, sql.ErrNoRows
	}
	var sourceType string
	if err = tx.QueryRow(`SELECT folder_type FROM folders WHERE id = ? AND account_id = ?`, sourceFolderID, accountID).Scan(&sourceType); err != nil {
		return nil, sql.ErrNoRows
	}
	for _, source := range sources {
		if sourceFolderID == destinationFolderID && source.Direction == "inbound" && sourceType != "trash" {
			continue // RFC 9051 permits copying within the selected mailbox.
		}
		if err = validateMessageMove(source.Direction, sourceType, destinationType, false); err != nil {
			return nil, err
		}
	}
	var written []string
	defer func() {
		if err != nil {
			for _, path := range written {
				_ = os.Remove(path)
			}
		}
	}()
	for index, source := range sources {
		var sourceUID int64
		var answered, deleted, draft int
		if err = tx.QueryRow(`SELECT s.uid, s.answered, s.deleted, s.draft
			FROM imap_message_state s JOIN messages m ON m.id=s.message_id
			WHERE s.message_id=? AND m.account_id=? AND s.folder_id=? AND m.folder_id=?`, source.ID, accountID, sourceFolderID, sourceFolderID).
			Scan(&sourceUID, &answered, &deleted, &draft); err != nil {
			return nil, sql.ErrNoRows
		}
		copyMessage := *source
		copyMessage.ID = 0
		copyMessage.FolderID = &destinationFolderID
		copyMessage.IsDeleted = destinationType == "trash"
		if err = reserveMailboxBytes(tx, accountID, copyMessage.Size); err != nil {
			return nil, err
		}
		var destinationID int64
		destinationID, err = saveMessage(tx, &copyMessage)
		if err != nil {
			return nil, err
		}
		if copyMessage.IsDeleted {
			if _, err = tx.Exec(`UPDATE messages SET is_deleted=1 WHERE id=?`, destinationID); err != nil {
				return nil, err
			}
		}
		if err = db.addIMAPMessageState(tx, destinationID, &copyMessage); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(`UPDATE imap_message_state SET answered=?, deleted=?, draft=? WHERE message_id=?`, answered, deleted, draft, destinationID); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(`INSERT INTO imap_keywords(message_id, keyword) SELECT ?, keyword FROM imap_keywords WHERE message_id=?`, destinationID, source.ID); err != nil {
			return nil, err
		}
		for attachmentIndex, attachment := range sourceAttachments[index] {
			sourcePath, ok := db.safeAttachmentPath(attachment.StoragePath)
			if !ok {
				return nil, fmt.Errorf("unsafe source attachment path")
			}
			data, readErr := ReadAttachmentFile(sourcePath)
			if readErr != nil {
				return nil, fmt.Errorf("reading copied attachment: %w", readErr)
			}
			name, nameErr := imapCopiedAttachmentName(destinationID, attachmentIndex, filepath.Ext(attachment.StoragePath))
			if nameErr != nil {
				return nil, nameErr
			}
			destinationPath, ok := db.safeAttachmentPath(name)
			if !ok {
				return nil, fmt.Errorf("unsafe destination attachment path")
			}
			if writeErr := WriteAttachmentFile(destinationPath, data); writeErr != nil {
				return nil, fmt.Errorf("writing copied attachment: %w", writeErr)
			}
			written = append(written, destinationPath)
			if _, err = saveAttachmentRecord(tx, &Attachment{MessageID: destinationID, Filename: attachment.Filename, ContentType: attachment.ContentType, Size: attachment.Size, StoragePath: name}); err != nil {
				return nil, err
			}
		}
		var destinationUID int64
		if err = tx.QueryRow(`SELECT uid FROM imap_message_state WHERE message_id=?`, destinationID).Scan(&destinationUID); err != nil {
			return nil, err
		}
		pairs = append(pairs, IMAPUIDPair{Source: uint32(sourceUID), Destination: uint32(destinationUID)})
	}
	if err = updateAccountFolderCounts(tx, accountID); err != nil {
		return nil, err
	}
	err = tx.Commit()
	if err == nil {
		db.NotifyIMAPChanges(accountID)
	}
	return pairs, err
}

func imapCopiedAttachmentName(messageID int64, index int, extension string) (string, error) {
	if len(extension) > 16 || strings.ContainsAny(extension, `/\\`) {
		extension = ".bin"
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d_imap_%d_%s%s", messageID, index, hex.EncodeToString(random), extension), nil
}

func (db *DB) MoveIMAPMessages(accountID, sourceFolderID, destinationFolderID int64, messageIDs []int64) ([]IMAPUIDPair, error) {
	if len(messageIDs) == 0 || len(messageIDs) > 500 {
		return nil, fmt.Errorf("invalid IMAP move selection")
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var destinationType string
	if err := tx.QueryRow(`SELECT folder_type FROM folders WHERE id=? AND account_id=?`, destinationFolderID, accountID).Scan(&destinationType); err != nil {
		return nil, sql.ErrNoRows
	}
	var sourceType string
	if err := tx.QueryRow(`SELECT folder_type FROM folders WHERE id=? AND account_id=?`, sourceFolderID, accountID).Scan(&sourceType); err != nil {
		return nil, sql.ErrNoRows
	}
	var pairs []IMAPUIDPair
	for _, messageID := range messageIDs {
		var sourceUID int64
		var direction string
		if err := tx.QueryRow(`SELECT s.uid, m.direction FROM imap_message_state s JOIN messages m ON m.id=s.message_id
			WHERE m.id=? AND m.account_id=? AND m.folder_id=? AND s.folder_id=?`, messageID, accountID, sourceFolderID, sourceFolderID).Scan(&sourceUID, &direction); err != nil {
			return nil, sql.ErrNoRows
		}
		if !(sourceFolderID == destinationFolderID && direction == "inbound" && sourceType != "trash") {
			if err := validateMessageMove(direction, sourceType, destinationType, true); err != nil {
				return nil, err
			}
		}
		if sourceFolderID == destinationFolderID {
			if _, err := db.recordIMAPExpunge(tx, sourceFolderID, uint32(sourceUID)); err != nil {
				return nil, err
			}
			uid, modseq, err := db.nextIMAPIdentity(tx, destinationFolderID)
			if err != nil {
				return nil, err
			}
			if _, err := tx.Exec(`UPDATE imap_message_state SET uid=?, modseq=?, deleted=0, recent=1 WHERE message_id=?`, uid, modseq, messageID); err != nil {
				return nil, err
			}
			pairs = append(pairs, IMAPUIDPair{Source: uint32(sourceUID), Destination: uint32(uid)})
			continue
		}
		if _, err := tx.Exec(`UPDATE messages SET folder_id=?, is_deleted=? WHERE id=? AND account_id=?`, destinationFolderID, boolToInt(destinationType == "trash"), messageID, accountID); err != nil {
			return nil, err
		}
		if err := db.moveIMAPMessageState(tx, messageID, destinationFolderID); err != nil {
			return nil, err
		}
		var destinationUID int64
		if err := tx.QueryRow(`SELECT uid FROM imap_message_state WHERE message_id=?`, messageID).Scan(&destinationUID); err != nil {
			return nil, err
		}
		pairs = append(pairs, IMAPUIDPair{Source: uint32(sourceUID), Destination: uint32(destinationUID)})
	}
	if err := updateAccountFolderCounts(tx, accountID); err != nil {
		return nil, err
	}
	err = tx.Commit()
	if err == nil {
		db.NotifyIMAPChanges(accountID)
	}
	return pairs, err
}

func (db *DB) ExpungeIMAPMessages(accountID, folderID int64, messageIDs []int64) ([]int64, error) {
	if len(messageIDs) == 0 {
		return nil, nil
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var paths []string
	var reclaimed int64
	for _, messageID := range messageIDs {
		var size int64
		var deleted int
		var uid uint32
		if err := tx.QueryRow(`SELECT m.size, s.deleted FROM messages m JOIN imap_message_state s ON s.message_id=m.id
			WHERE m.id=? AND m.account_id=? AND m.folder_id=? AND s.folder_id=?`, messageID, accountID, folderID, folderID).Scan(&size, &deleted); err != nil || deleted == 0 {
			return nil, sql.ErrNoRows
		}
		if err := tx.QueryRow(`SELECT uid FROM imap_message_state WHERE message_id=?`, messageID).Scan(&uid); err != nil {
			return nil, err
		}
		rows, err := tx.Query(`SELECT storage_path FROM attachments WHERE message_id=?`, messageID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var path string
			if err := rows.Scan(&path); err != nil {
				rows.Close()
				return nil, err
			}
			paths = append(paths, path)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
		if _, err := db.recordIMAPExpunge(tx, folderID, uid); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`DELETE FROM messages WHERE id=? AND account_id=?`, messageID, accountID); err != nil {
			return nil, err
		}
		reclaimed += size
	}
	if err := releaseMailboxBytes(tx, accountID, reclaimed); err != nil {
		return nil, err
	}
	if err := updateAccountFolderCounts(tx, accountID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	db.NotifyIMAPChanges(accountID)
	for _, path := range paths {
		if fullPath, ok := db.safeAttachmentPath(path); ok {
			_ = os.Remove(fullPath)
		}
	}
	return messageIDs, nil
}

func updateAccountFolderCounts(exec sqlExecutor, accountID int64) error {
	_, err := exec.Exec(`UPDATE folders SET
		total_count=(SELECT COUNT(*) FROM messages WHERE folder_id=folders.id AND is_deleted=(folders.folder_type='trash')),
		unread_count=(SELECT COUNT(*) FROM messages WHERE folder_id=folders.id AND is_read=0 AND is_deleted=(folders.folder_type='trash'))
		WHERE account_id=?`, accountID)
	return err
}
