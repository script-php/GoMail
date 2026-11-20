package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const maxIMAPIdentifier = int64(^uint32(0))

// IMAPMailboxState contains the persistent synchronization identity for one
// folder. Values are never reset while the folder exists.
type IMAPMailboxState struct {
	FolderID      int64
	UIDValidity   uint32
	UIDNext       uint32
	HighestModSeq uint64
}

// IMAPMessageState is the protocol state that does not map cleanly onto
// GoMail's webmail fields. Seen and Flagged remain sourced from messages.
type IMAPMessageState struct {
	MessageID int64
	FolderID  int64
	UID       uint32
	ModSeq    uint64
	Answered  bool
	Deleted   bool
	Draft     bool
	Recent    bool
}

type IMAPMailboxSnapshot struct {
	Exists      int
	Recent      int
	Unseen      int
	FirstUnseen int
	RecentIDs   []int64
}

type IMAPMessageRef struct {
	Sequence  uint32
	MessageID int64
	UID       uint32
	ModSeq    uint64
	Seen      bool
	Flagged   bool
	Answered  bool
	Deleted   bool
	Draft     bool
	Recent    bool
	Keywords  []string
}

type IMAPExpunge struct {
	UID    uint32
	ModSeq uint64
}

type IMAPFlagMutation struct {
	Mode     string
	Seen     *bool
	Flagged  *bool
	Answered *bool
	Deleted  *bool
	Draft    *bool
	Keywords []string
}

type IMAPAppendAttachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

func newUIDValidity() uint32 {
	var value [4]byte
	if _, err := rand.Read(value[:]); err == nil {
		result := binary.BigEndian.Uint32(value[:])
		if result != 0 {
			return result
		}
	}
	// UIDVALIDITY only needs to be non-zero and change when a mailbox is
	// recreated. Folder identifiers are never reused by either backend.
	result := uint32(time.Now().Unix())
	if result == 0 {
		return 1
	}
	return result
}

func (db *DB) ensureIMAPMailbox(exec sqlExecutor, folderID int64) error {
	if folderID <= 0 {
		return fmt.Errorf("invalid folder id")
	}
	var existing int64
	err := exec.QueryRow(`SELECT folder_id FROM imap_mailboxes WHERE folder_id = ?`, folderID).Scan(&existing)
	if err == nil {
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	query := `INSERT INTO imap_mailboxes(folder_id, uid_validity, uid_next, highest_modseq) VALUES(?, ?, 1, 1) ON CONFLICT(folder_id) DO NOTHING`
	if db.IsMySQL() {
		query = `INSERT INTO imap_mailboxes(folder_id, uid_validity, uid_next, highest_modseq) VALUES(?, ?, 1, 1) ON DUPLICATE KEY UPDATE folder_id = folder_id`
	}
	_, err = exec.Exec(query, folderID, int64(newUIDValidity()))
	return err
}

// addIMAPMessageState allocates a UID and mod-sequence in the same transaction
// that creates the message. This prevents visible messages without an IMAP UID.
func (db *DB) addIMAPMessageState(tx *sql.Tx, messageID int64, message *Message) error {
	if message.FolderID == nil || *message.FolderID <= 0 {
		// System-generated queue records and pre-folder compatibility callers can
		// intentionally create an unfiled message. Such rows are not visible to
		// IMAP until they are assigned to a mailbox.
		return nil
	}
	var existing int64
	err := tx.QueryRow(`SELECT message_id FROM imap_message_state WHERE message_id = ?`, messageID).Scan(&existing)
	if err == nil {
		return nil
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("checking IMAP message state: %w", err)
	}
	if err := db.ensureIMAPMailbox(tx, *message.FolderID); err != nil {
		return fmt.Errorf("ensuring IMAP mailbox state: %w", err)
	}
	result, err := tx.Exec(`UPDATE imap_mailboxes
		SET uid_next = uid_next + 1, highest_modseq = highest_modseq + 1
		WHERE folder_id = ? AND uid_next <= ?`, *message.FolderID, maxIMAPIdentifier)
	if err != nil {
		return fmt.Errorf("allocating IMAP UID: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return fmt.Errorf("checking IMAP UID allocation: %w", err)
		}
		return fmt.Errorf("IMAP UID space exhausted for folder %d", *message.FolderID)
	}
	var uid, modseq int64
	if err := tx.QueryRow(`SELECT uid_next - 1, highest_modseq FROM imap_mailboxes WHERE folder_id = ?`, *message.FolderID).Scan(&uid, &modseq); err != nil {
		return fmt.Errorf("reading allocated IMAP UID: %w", err)
	}
	_, err = tx.Exec(`INSERT INTO imap_message_state
		(message_id, folder_id, uid, modseq, answered, deleted, draft, recent)
		VALUES(?, ?, ?, ?, 0, 0, ?, 1)`, messageID, *message.FolderID, uid, modseq, boolToInt(strings.EqualFold(message.Direction, "draft")))
	if err != nil {
		return fmt.Errorf("saving IMAP message state: %w", err)
	}
	return nil
}

func (db *DB) nextIMAPIdentity(tx *sql.Tx, folderID int64) (int64, int64, error) {
	if err := db.ensureIMAPMailbox(tx, folderID); err != nil {
		return 0, 0, err
	}
	result, err := tx.Exec(`UPDATE imap_mailboxes
		SET uid_next = uid_next + 1, highest_modseq = highest_modseq + 1
		WHERE folder_id = ? AND uid_next <= ?`, folderID, maxIMAPIdentifier)
	if err != nil {
		return 0, 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		if err != nil {
			return 0, 0, err
		}
		return 0, 0, fmt.Errorf("IMAP UID space exhausted for folder %d", folderID)
	}
	var uid, modseq int64
	err = tx.QueryRow(`SELECT uid_next - 1, highest_modseq FROM imap_mailboxes WHERE folder_id = ?`, folderID).Scan(&uid, &modseq)
	return uid, modseq, err
}

func (db *DB) touchIMAPMessageState(tx *sql.Tx, messageID int64) error {
	var folderID int64
	err := tx.QueryRow(`SELECT folder_id FROM imap_message_state WHERE message_id = ?`, messageID).Scan(&folderID)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE imap_mailboxes SET highest_modseq = highest_modseq + 1 WHERE folder_id = ?`, folderID); err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE imap_message_state SET modseq = (SELECT highest_modseq FROM imap_mailboxes WHERE folder_id = ?) WHERE message_id = ?`, folderID, messageID)
	return err
}

func (db *DB) moveIMAPMessageState(tx *sql.Tx, messageID, targetFolderID int64) error {
	var sourceFolderID, sourceUID int64
	err := tx.QueryRow(`SELECT folder_id, uid FROM imap_message_state WHERE message_id = ?`, messageID).Scan(&sourceFolderID, &sourceUID)
	if err == sql.ErrNoRows {
		return db.addIMAPMessageState(tx, messageID, &Message{FolderID: &targetFolderID})
	}
	if err != nil {
		return err
	}
	if sourceFolderID == targetFolderID {
		return db.touchIMAPMessageState(tx, messageID)
	}
	uid, modseq, err := db.nextIMAPIdentity(tx, targetFolderID)
	if err != nil {
		return err
	}
	if _, err := db.recordIMAPExpunge(tx, sourceFolderID, uint32(sourceUID)); err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE imap_message_state SET folder_id = ?, uid = ?, modseq = ?, deleted = 0, recent = 1 WHERE message_id = ?`, targetFolderID, uid, modseq, messageID)
	return err
}

// recordIMAPExpunge advances the mailbox modification sequence and records the
// removed UID in the same transaction as the removal or move.
func (db *DB) recordIMAPExpunge(tx *sql.Tx, folderID int64, uid uint32) (uint64, error) {
	if uid == 0 {
		return 0, fmt.Errorf("invalid expunged UID")
	}
	if _, err := tx.Exec(`UPDATE imap_mailboxes SET highest_modseq=highest_modseq+1 WHERE folder_id=?`, folderID); err != nil {
		return 0, err
	}
	var modseq uint64
	if err := tx.QueryRow(`SELECT highest_modseq FROM imap_mailboxes WHERE folder_id=?`, folderID).Scan(&modseq); err != nil {
		return 0, err
	}
	query := `INSERT INTO imap_expunge_history(folder_id,uid,modseq) VALUES(?,?,?)
		ON CONFLICT(folder_id,uid) DO UPDATE SET modseq=excluded.modseq, expunged_at=CURRENT_TIMESTAMP`
	if db.IsMySQL() {
		query = `INSERT INTO imap_expunge_history(folder_id,uid,modseq) VALUES(?,?,?)
			ON DUPLICATE KEY UPDATE modseq=VALUES(modseq), expunged_at=CURRENT_TIMESTAMP`
	}
	if _, err := tx.Exec(query, folderID, uid, modseq); err != nil {
		return 0, err
	}
	return modseq, nil
}

func (db *DB) GetIMAPExpunges(accountID, folderID int64, afterModSeq uint64) ([]IMAPExpunge, error) {
	rows, err := db.Query(`SELECT h.uid,h.modseq FROM imap_expunge_history h
		JOIN folders f ON f.id=h.folder_id WHERE h.folder_id=? AND f.account_id=? AND h.modseq>? ORDER BY h.uid`, folderID, accountID, afterModSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []IMAPExpunge
	for rows.Next() {
		var uid, modseq uint64
		if err := rows.Scan(&uid, &modseq); err != nil {
			return nil, err
		}
		if uid == 0 || uid > uint64(^uint32(0)) {
			return nil, fmt.Errorf("invalid stored expunged UID")
		}
		result = append(result, IMAPExpunge{UID: uint32(uid), ModSeq: modseq})
	}
	return result, rows.Err()
}

// initializeIMAPState backfills existing folders and messages. It is one
// transaction so an interrupted migration cannot publish partial UID state.
func (db *DB) initializeIMAPState() error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT id FROM folders ORDER BY id`)
	if err != nil {
		return err
	}
	var folderIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		folderIDs = append(folderIDs, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, folderID := range folderIDs {
		if err := db.ensureIMAPMailbox(tx, folderID); err != nil {
			return err
		}
	}
	rows, err = tx.Query(`SELECT id, folder_id, direction FROM messages WHERE folder_id IS NOT NULL ORDER BY folder_id, received_at, id`)
	if err != nil {
		return err
	}
	type existingMessage struct {
		id, folderID int64
		direction    string
	}
	var messages []existingMessage
	for rows.Next() {
		var message existingMessage
		if err := rows.Scan(&message.id, &message.folderID, &message.direction); err != nil {
			rows.Close()
			return err
		}
		messages = append(messages, message)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, existing := range messages {
		folderID := existing.folderID
		if err := db.addIMAPMessageState(tx, existing.id, &Message{FolderID: &folderID, Direction: existing.direction}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) GetIMAPMailboxState(accountID, folderID int64) (*IMAPMailboxState, error) {
	state := &IMAPMailboxState{}
	var validity, next, modseq int64
	err := db.QueryRow(`SELECT m.folder_id, m.uid_validity, m.uid_next, m.highest_modseq
		FROM imap_mailboxes m JOIN folders f ON f.id = m.folder_id
		WHERE m.folder_id = ? AND f.account_id = ?`, folderID, accountID).
		Scan(&state.FolderID, &validity, &next, &modseq)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	state.UIDValidity, state.UIDNext, state.HighestModSeq = uint32(validity), uint32(next), uint64(modseq)
	return state, nil
}

func (db *DB) GetIMAPMessageState(accountID, messageID int64) (*IMAPMessageState, error) {
	state := &IMAPMessageState{}
	var uid, modseq int64
	var answered, deleted, draft, recent int
	err := db.QueryRow(`SELECT s.message_id, s.folder_id, s.uid, s.modseq, s.answered, s.deleted, s.draft, s.recent
		FROM imap_message_state s JOIN messages m ON m.id = s.message_id
		WHERE s.message_id = ? AND m.account_id = ?`, messageID, accountID).
		Scan(&state.MessageID, &state.FolderID, &uid, &modseq, &answered, &deleted, &draft, &recent)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	state.UID, state.ModSeq = uint32(uid), uint64(modseq)
	state.Answered, state.Deleted, state.Draft, state.Recent = answered != 0, deleted != 0, draft != 0, recent != 0
	return state, nil
}

// OpenIMAPMailbox returns a consistent count snapshot and claims the persistent
// recent markers for this selection. Recent is advisory in IMAP4rev1 and is not
// part of the permanent flag set.
func (db *DB) OpenIMAPMailbox(accountID, folderID int64) (IMAPMailboxSnapshot, error) {
	return db.imapMailboxSnapshot(accountID, folderID, true)
}

func (db *DB) GetIMAPMailboxSnapshot(accountID, folderID int64) (IMAPMailboxSnapshot, error) {
	return db.imapMailboxSnapshot(accountID, folderID, false)
}

func (db *DB) imapMailboxSnapshot(accountID, folderID int64, claimRecent bool) (IMAPMailboxSnapshot, error) {
	tx, err := db.Begin()
	if err != nil {
		return IMAPMailboxSnapshot{}, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT m.id, m.is_read, s.recent
		FROM messages m JOIN imap_message_state s ON s.message_id = m.id
		WHERE m.account_id = ? AND m.folder_id = ? ORDER BY s.uid`, accountID, folderID)
	if err != nil {
		return IMAPMailboxSnapshot{}, err
	}
	var snapshot IMAPMailboxSnapshot
	for rows.Next() {
		var messageID int64
		var seen, recent int
		if err := rows.Scan(&messageID, &seen, &recent); err != nil {
			rows.Close()
			return snapshot, err
		}
		snapshot.Exists++
		if recent != 0 {
			snapshot.Recent++
			if claimRecent {
				snapshot.RecentIDs = append(snapshot.RecentIDs, messageID)
			}
		}
		if seen == 0 {
			snapshot.Unseen++
			if snapshot.FirstUnseen == 0 {
				snapshot.FirstUnseen = snapshot.Exists
			}
		}
	}
	if err := rows.Close(); err != nil {
		return snapshot, err
	}
	if claimRecent {
		if _, err := tx.Exec(`UPDATE imap_message_state SET recent = 0 WHERE folder_id = ? AND message_id IN (SELECT id FROM messages WHERE account_id = ?)`, folderID, accountID); err != nil {
			return snapshot, err
		}
	}
	return snapshot, tx.Commit()
}

// ClaimIMAPRecent atomically gives one selected session ownership of newly
// delivered \Recent messages. Other sessions subsequently observe them as old.
func (db *DB) ClaimIMAPRecent(accountID, folderID int64) ([]int64, error) {
	snapshot, err := db.imapMailboxSnapshot(accountID, folderID, true)
	return snapshot.RecentIDs, err
}

func (db *DB) SetIMAPSubscription(accountID, folderID int64, subscribed bool) error {
	var exists int
	if err := db.QueryRow(`SELECT COUNT(*) FROM folders WHERE id = ? AND account_id = ?`, folderID, accountID).Scan(&exists); err != nil {
		return err
	}
	if exists != 1 {
		return sql.ErrNoRows
	}
	if !subscribed {
		_, err := db.Exec(`DELETE FROM imap_subscriptions WHERE account_id = ? AND folder_id = ?`, accountID, folderID)
		return err
	}
	query := `INSERT INTO imap_subscriptions(account_id, folder_id) VALUES(?, ?) ON CONFLICT(account_id, folder_id) DO NOTHING`
	if db.IsMySQL() {
		query = `INSERT INTO imap_subscriptions(account_id, folder_id) VALUES(?, ?) ON DUPLICATE KEY UPDATE folder_id = folder_id`
	}
	_, err := db.Exec(query, accountID, folderID)
	return err
}

func (db *DB) ListIMAPFolders(accountID int64, subscribedOnly bool) ([]*Folder, error) {
	query := `SELECT f.id, f.account_id, f.name, f.folder_type, f.is_default, f.unread_count, f.total_count FROM folders f WHERE f.account_id = ?`
	if subscribedOnly {
		query += ` AND EXISTS (SELECT 1 FROM imap_subscriptions s WHERE s.account_id = f.account_id AND s.folder_id = f.id)`
	}
	query += ` ORDER BY CASE WHEN LOWER(f.name) = 'inbox' THEN 0 ELSE 1 END, f.name`
	rows, err := db.Query(query, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var folders []*Folder
	for rows.Next() {
		folder := &Folder{}
		if err := rows.Scan(&folder.ID, &folder.AccountID, &folder.Name, &folder.FolderType, &folder.IsDefault, &folder.UnreadCount, &folder.TotalCount); err != nil {
			return nil, err
		}
		folders = append(folders, folder)
	}
	return folders, rows.Err()
}

func (db *DB) ListIMAPMessageRefs(accountID, folderID int64) ([]IMAPMessageRef, error) {
	rows, err := db.Query(`SELECT s.message_id, s.uid, s.modseq, m.is_read, m.is_starred,
		s.answered, s.deleted, s.draft, s.recent
		FROM imap_message_state s JOIN messages m ON m.id = s.message_id
		WHERE m.account_id = ? AND s.folder_id = ? AND m.folder_id = ? ORDER BY s.uid`, accountID, folderID, folderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var refs []IMAPMessageRef
	for rows.Next() {
		var ref IMAPMessageRef
		var seen, flagged, answered, deleted, draft, recent int
		if err := rows.Scan(&ref.MessageID, &ref.UID, &ref.ModSeq, &seen, &flagged, &answered, &deleted, &draft, &recent); err != nil {
			return nil, err
		}
		ref.Sequence = uint32(len(refs) + 1)
		ref.Seen, ref.Flagged, ref.Answered = seen != 0, flagged != 0, answered != 0
		ref.Deleted, ref.Draft, ref.Recent = deleted != 0, draft != 0, recent != 0
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range refs {
		keywordRows, err := db.Query(`SELECT keyword FROM imap_keywords WHERE message_id = ? ORDER BY keyword`, refs[index].MessageID)
		if err != nil {
			return nil, err
		}
		for keywordRows.Next() {
			var keyword string
			if err := keywordRows.Scan(&keyword); err != nil {
				keywordRows.Close()
				return nil, err
			}
			refs[index].Keywords = append(refs[index].Keywords, keyword)
		}
		if err := keywordRows.Close(); err != nil {
			return nil, err
		}
	}
	return refs, nil
}

func (db *DB) CreateIMAPFolder(accountID int64, name string) (*Folder, error) {
	name = strings.TrimSpace(name)
	if err := validateIMAPFolderName(name); err != nil {
		return nil, err
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO folders(account_id,name,folder_type,is_default) VALUES(?,?,'custom',0)`, accountID, name)
	if err != nil {
		return nil, fmt.Errorf("creating mailbox: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}
	if err := db.ensureIMAPMailbox(tx, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	db.NotifyIMAPChanges(accountID)
	return &Folder{ID: id, AccountID: accountID, Name: name, FolderType: "custom"}, nil
}

func (db *DB) RenameIMAPFolder(accountID, folderID int64, name string) error {
	name = strings.TrimSpace(name)
	if err := validateIMAPFolderName(name); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var oldName, folderType string
	var isDefault int
	if err := tx.QueryRow(`SELECT name, folder_type, is_default FROM folders WHERE id=? AND account_id=?`, folderID, accountID).Scan(&oldName, &folderType, &isDefault); err != nil {
		return sql.ErrNoRows
	}
	if isDefault != 0 && folderType != "inbox" {
		return fmt.Errorf("default mailbox cannot be renamed")
	}
	if strings.HasPrefix(strings.ToLower(name), strings.ToLower(oldName)+"/") {
		return fmt.Errorf("mailbox cannot be renamed beneath itself")
	}
	rows, err := tx.Query(`SELECT id, name FROM folders WHERE account_id=?`, accountID)
	if err != nil {
		return err
	}
	type renameTarget struct {
		id       int64
		old, new string
	}
	var all []renameTarget
	for rows.Next() {
		var target renameTarget
		if err := rows.Scan(&target.id, &target.old); err != nil {
			rows.Close()
			return err
		}
		all = append(all, target)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	renamed := make(map[int64]bool)
	for index := range all {
		if all[index].id == folderID {
			all[index].new = name
			renamed[all[index].id] = true
		} else if strings.HasPrefix(strings.ToLower(all[index].old), strings.ToLower(oldName)+"/") {
			all[index].new = name + all[index].old[len(oldName):]
			renamed[all[index].id] = true
		}
	}
	for _, target := range all {
		if renamed[target.id] {
			continue
		}
		for _, candidate := range all {
			if renamed[candidate.id] && strings.EqualFold(target.old, candidate.new) {
				return fmt.Errorf("destination mailbox already exists")
			}
		}
	}
	for _, target := range all {
		if !renamed[target.id] {
			continue
		}
		if _, err := tx.Exec(`UPDATE folders SET name=? WHERE id=? AND account_id=?`, target.new, target.id, accountID); err != nil {
			return err
		}
	}
	if folderType == "inbox" {
		if _, err := tx.Exec(`UPDATE folders SET folder_type='custom', is_default=0 WHERE id=?`, folderID); err != nil {
			return err
		}
		result, err := tx.Exec(`INSERT INTO folders(account_id,name,folder_type,is_default) VALUES(?,'Inbox','inbox',1)`, accountID)
		if err != nil {
			return err
		}
		newInboxID, err := result.LastInsertId()
		if err != nil {
			return err
		}
		if err := db.ensureIMAPMailbox(tx, newInboxID); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO imap_subscriptions(account_id,folder_id) VALUES(?,?)`, accountID, newInboxID); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err == nil {
		db.NotifyIMAPChanges(accountID)
	}
	return err
}

func (db *DB) DeleteIMAPFolder(accountID, folderID int64) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var name string
	var isDefault, messages int
	if err := tx.QueryRow(`SELECT name, is_default, (SELECT COUNT(*) FROM messages WHERE folder_id=folders.id) FROM folders WHERE id=? AND account_id=?`, folderID, accountID).Scan(&name, &isDefault, &messages); err != nil {
		return sql.ErrNoRows
	}
	if isDefault != 0 {
		return fmt.Errorf("default mailbox cannot be deleted")
	}
	if messages != 0 {
		return fmt.Errorf("mailbox is not empty")
	}
	prefix := name + "/"
	var children int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM folders WHERE account_id=? AND lower(substr(name,1,?))=lower(?)`, accountID, utf8.RuneCountInString(prefix), prefix).Scan(&children); err != nil {
		return err
	}
	if children != 0 {
		return fmt.Errorf("mailbox has children")
	}
	if _, err := tx.Exec(`DELETE FROM folders WHERE id=? AND account_id=?`, folderID, accountID); err != nil {
		return err
	}
	if err = tx.Commit(); err == nil {
		db.NotifyIMAPChanges(accountID)
	}
	return err
}

func validateIMAPFolderName(name string) error {
	if name == "" || len(name) > 255 || strings.EqualFold(name, "INBOX") || strings.ContainsAny(name, "\x00\r\n") {
		return fmt.Errorf("invalid mailbox name")
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("invalid mailbox hierarchy")
		}
	}
	return nil
}

func (db *DB) UpdateIMAPFlags(accountID, folderID int64, messageIDs []int64, mutation IMAPFlagMutation) error {
	if mutation.Mode != "replace" && mutation.Mode != "add" && mutation.Mode != "remove" {
		return fmt.Errorf("invalid IMAP flag mutation")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := db.updateIMAPFlagsTx(tx, accountID, folderID, messageIDs, mutation); err != nil {
		return err
	}
	if err = tx.Commit(); err == nil {
		db.NotifyIMAPChanges(accountID)
	}
	return err
}

// UpdateIMAPFlagsConditional implements CONDSTORE UNCHANGEDSINCE atomically.
// Messages whose current mod-sequence is newer than maxModSeq are returned and
// left untouched.
func (db *DB) UpdateIMAPFlagsConditional(accountID, folderID int64, messageIDs []int64, maxModSeq uint64, mutation IMAPFlagMutation) ([]int64, error) {
	if mutation.Mode != "replace" && mutation.Mode != "add" && mutation.Mode != "remove" {
		return nil, fmt.Errorf("invalid IMAP flag mutation")
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var eligible, modified []int64
	for _, messageID := range messageIDs {
		var modseq uint64
		if err := tx.QueryRow(`SELECT s.modseq FROM imap_message_state s JOIN messages m ON m.id=s.message_id
			WHERE m.id=? AND m.account_id=? AND m.folder_id=? AND s.folder_id=?`, messageID, accountID, folderID, folderID).Scan(&modseq); err != nil {
			return nil, sql.ErrNoRows
		}
		if modseq > maxModSeq {
			modified = append(modified, messageID)
		} else {
			eligible = append(eligible, messageID)
		}
	}
	if len(eligible) > 0 {
		if err := db.updateIMAPFlagsTx(tx, accountID, folderID, eligible, mutation); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if len(eligible) > 0 {
		db.NotifyIMAPChanges(accountID)
	}
	return modified, nil
}

func (db *DB) updateIMAPFlagsTx(tx *sql.Tx, accountID, folderID int64, messageIDs []int64, mutation IMAPFlagMutation) error {
	for _, messageID := range messageIDs {
		var exists int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM messages m JOIN imap_message_state s ON s.message_id = m.id WHERE m.id = ? AND m.account_id = ? AND m.folder_id = ? AND s.folder_id = ?`, messageID, accountID, folderID, folderID).Scan(&exists); err != nil {
			return err
		}
		if exists != 1 {
			return sql.ErrNoRows
		}
		if mutation.Seen != nil {
			if _, err := tx.Exec(`UPDATE messages SET is_read = ? WHERE id = ?`, boolToInt(*mutation.Seen), messageID); err != nil {
				return err
			}
		}
		if mutation.Flagged != nil {
			if _, err := tx.Exec(`UPDATE messages SET is_starred = ? WHERE id = ?`, boolToInt(*mutation.Flagged), messageID); err != nil {
				return err
			}
		}
		for column, value := range map[string]*bool{"answered": mutation.Answered, "deleted": mutation.Deleted, "draft": mutation.Draft} {
			if value != nil {
				if _, err := tx.Exec(`UPDATE imap_message_state SET `+column+` = ? WHERE message_id = ?`, boolToInt(*value), messageID); err != nil {
					return err
				}
			}
		}
		if mutation.Mode == "replace" {
			if _, err := tx.Exec(`DELETE FROM imap_keywords WHERE message_id = ?`, messageID); err != nil {
				return err
			}
		}
		for _, keyword := range mutation.Keywords {
			if mutation.Mode == "remove" {
				if _, err := tx.Exec(`DELETE FROM imap_keywords WHERE message_id = ? AND keyword = ?`, messageID, keyword); err != nil {
					return err
				}
				continue
			}
			query := `INSERT INTO imap_keywords(message_id, keyword) VALUES(?, ?) ON CONFLICT(message_id, keyword) DO NOTHING`
			if db.IsMySQL() {
				query = `INSERT INTO imap_keywords(message_id, keyword) VALUES(?, ?) ON DUPLICATE KEY UPDATE keyword = keyword`
			}
			if _, err := tx.Exec(query, messageID, keyword); err != nil {
				return err
			}
		}
		if err := db.touchIMAPMessageState(tx, messageID); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) AppendIMAPMessage(message *Message, mutation IMAPFlagMutation) (int64, uint32, error) {
	return db.AppendIMAPMessageWithAttachments(message, mutation, nil)
}

// AppendIMAPMessageWithAttachments persists the message, UID/flags and all
// attachment metadata in one database transaction. Files written before the
// commit are removed on every rollback path.
func (db *DB) AppendIMAPMessageWithAttachments(message *Message, mutation IMAPFlagMutation, attachments []IMAPAppendAttachment) (id int64, uid uint32, err error) {
	if message == nil || message.FolderID == nil {
		return 0, 0, fmt.Errorf("APPEND requires a mailbox")
	}
	required := message.Size
	for _, attachment := range attachments {
		required += int64(len(attachment.Data))
	}
	if err := db.EnsureDiskSpace(required); err != nil {
		return 0, 0, err
	}
	if mutation.Mode != "replace" && mutation.Mode != "add" && mutation.Mode != "remove" {
		return 0, 0, fmt.Errorf("invalid IMAP flag mutation")
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	var written []string
	defer func() {
		if err != nil {
			for _, path := range written {
				_ = os.Remove(path)
			}
		}
	}()
	var exists int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM folders WHERE id=? AND account_id=?`, *message.FolderID, message.AccountID).Scan(&exists); err != nil || exists != 1 {
		return 0, 0, sql.ErrNoRows
	}
	prepareMessageSize(message)
	message.HasAttachments = len(attachments) > 0
	if err := reserveMailboxBytes(tx, message.AccountID, message.Size); err != nil {
		return 0, 0, err
	}
	id, err = saveMessage(tx, message)
	if err != nil {
		return 0, 0, err
	}
	if err := db.addIMAPMessageState(tx, id, message); err != nil {
		return 0, 0, err
	}
	for index, attachment := range attachments {
		extension := filepath.Ext(attachment.Filename)
		if !validIMAPAttachmentExtension(extension) {
			extension = ".bin"
		}
		storedName, nameErr := newAttachmentName(id, "imap", index, attachment.Data, extension)
		if nameErr != nil {
			return 0, 0, nameErr
		}
		fullPath, safe := db.safeAttachmentPath(storedName)
		if !safe {
			return 0, 0, fmt.Errorf("unsafe APPEND attachment path")
		}
		if err = WriteAttachmentFile(fullPath, attachment.Data); err != nil {
			return 0, 0, fmt.Errorf("writing APPEND attachment: %w", err)
		}
		written = append(written, fullPath)
		if _, err = saveAttachmentRecord(tx, &Attachment{MessageID: id, Filename: attachment.Filename, ContentType: attachment.ContentType, Size: int64(len(attachment.Data)), StoragePath: storedName}); err != nil {
			return 0, 0, err
		}
	}
	if message.IsDeleted {
		if _, err := tx.Exec(`UPDATE messages SET is_deleted=1 WHERE id=?`, id); err != nil {
			return 0, 0, err
		}
	}
	if err := db.updateIMAPFlagsTx(tx, message.AccountID, *message.FolderID, []int64{id}, mutation); err != nil {
		return 0, 0, err
	}
	var allocatedUID int64
	if err := tx.QueryRow(`SELECT uid FROM imap_message_state WHERE message_id=?`, id).Scan(&allocatedUID); err != nil {
		return 0, 0, err
	}
	if err := updateAccountFolderCounts(tx, message.AccountID); err != nil {
		return 0, 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, 0, err
	}
	db.NotifyIMAPChanges(message.AccountID)
	return id, uint32(allocatedUID), nil
}

func validIMAPAttachmentExtension(extension string) bool {
	if extension == "" || len(extension) > 16 || extension[0] != '.' {
		return false
	}
	for _, char := range extension[1:] {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}
