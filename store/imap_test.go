package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func openIMAPTestDB(t *testing.T) *DB {
	t.Helper()
	root := t.TempDir()
	db, err := Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.com'); INSERT INTO accounts(id,domain_id,email,password_hash) VALUES(1,1,'one@example.com','x')`); err != nil {
		t.Fatal(err)
	}
	if err := db.DefaultFolders(1); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestIMAPAppendPersistsAttachmentsWithMessage(t *testing.T) {
	db := openIMAPTestDB(t)
	drafts, _ := db.GetFolderByType(1, "drafts")
	message := &Message{AccountID: 1, FolderID: &drafts.ID, MessageID: "append-attachment", Direction: "draft", RawMessage: []byte("Subject: attached\r\n\r\nbody"), ReceivedAt: time.Now()}
	id, uid, err := db.AppendIMAPMessageWithAttachments(message, IMAPFlagMutation{Mode: "replace"}, []IMAPAppendAttachment{{Filename: "document.txt", ContentType: "text/plain", Data: []byte("attachment data")}})
	if err != nil || uid == 0 {
		t.Fatalf("APPEND id=%d uid=%d err=%v", id, uid, err)
	}
	stored, _ := db.GetMessage(id, 1)
	attachments, err := db.GetAttachments(id)
	if err != nil || stored == nil || !stored.HasAttachments || len(attachments) != 1 {
		t.Fatalf("message=%#v attachments=%#v err=%v", stored, attachments, err)
	}
	path, safe := db.safeAttachmentPath(attachments[0].StoragePath)
	data, readErr := os.ReadFile(path)
	if !safe || readErr != nil || string(data) != "attachment data" {
		t.Fatalf("attachment path=%q safe=%v data=%q err=%v", path, safe, data, readErr)
	}
}

func TestIMAPConcurrentUIDAllocation(t *testing.T) {
	db := openIMAPTestDB(t)
	inbox, _ := db.GetFolderByType(1, "inbox")
	const count = 24
	var wait sync.WaitGroup
	errors := make(chan error, count)
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: fmt.Sprintf("concurrent-%d", index), Direction: "inbound", ReceivedAt: time.Now()})
			errors <- err
		}(index)
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	refs, err := db.ListIMAPMessageRefs(1, inbox.ID)
	if err != nil || len(refs) != count {
		t.Fatalf("refs=%d err=%v", len(refs), err)
	}
	seen := make(map[uint32]bool, count)
	for _, ref := range refs {
		if ref.UID == 0 || seen[ref.UID] {
			t.Fatalf("invalid/reused UID %d in %#v", ref.UID, refs)
		}
		seen[ref.UID] = true
	}
	mailbox, _ := db.GetIMAPMailboxState(1, inbox.ID)
	if mailbox.UIDNext != count+1 {
		t.Fatalf("UIDNEXT=%d want=%d", mailbox.UIDNext, count+1)
	}
}

func TestIMAPConditionalStoreIsAtomic(t *testing.T) {
	db := openIMAPTestDB(t)
	inbox, _ := db.GetFolderByType(1, "inbox")
	id, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "conditional", Direction: "inbound", ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	initial, _ := db.GetIMAPMessageState(1, id)
	if err := db.MarkRead(id); err != nil {
		t.Fatal(err)
	}
	flagged := true
	mutation := IMAPFlagMutation{Mode: "add", Flagged: &flagged}
	modified, err := db.UpdateIMAPFlagsConditional(1, inbox.ID, []int64{id}, initial.ModSeq, mutation)
	if err != nil || len(modified) != 1 || modified[0] != id {
		t.Fatalf("stale conditional STORE modified=%v err=%v", modified, err)
	}
	message, _ := db.GetMessage(id, 1)
	if message.IsStarred {
		t.Fatal("stale conditional STORE changed flags")
	}
	current, _ := db.GetIMAPMessageState(1, id)
	modified, err = db.UpdateIMAPFlagsConditional(1, inbox.ID, []int64{id}, current.ModSeq, mutation)
	if err != nil || len(modified) != 0 {
		t.Fatalf("current conditional STORE modified=%v err=%v", modified, err)
	}
	message, _ = db.GetMessage(id, 1)
	if !message.IsStarred {
		t.Fatal("current conditional STORE did not change flags")
	}
}

func TestIMAPUIDsAreStableMonotonicAndChangeOnMove(t *testing.T) {
	db := openIMAPTestDB(t)
	inbox, _ := db.GetFolderByType(1, "inbox")
	trash, _ := db.GetFolderByType(1, "trash")
	mailbox, err := db.GetIMAPMailboxState(1, inbox.ID)
	if err != nil || mailbox == nil || mailbox.UIDValidity == 0 || mailbox.UIDNext != 1 {
		t.Fatalf("initial mailbox state = %#v, %v", mailbox, err)
	}
	first, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "one", Direction: "inbound", ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "two", Direction: "inbound", ReceivedAt: time.Now().Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	firstState, _ := db.GetIMAPMessageState(1, first)
	secondState, _ := db.GetIMAPMessageState(1, second)
	if firstState.UID != 1 || secondState.UID != 2 {
		t.Fatalf("allocated UIDs = %d, %d; want 1, 2", firstState.UID, secondState.UID)
	}
	if err := db.ApplyMessageAction(1, []int64{first}, "trash", 0); err != nil {
		t.Fatal(err)
	}
	trashed, _ := db.GetIMAPMessageState(1, first)
	if trashed.FolderID != trash.ID || trashed.UID != 1 {
		t.Fatalf("trash state = %#v", trashed)
	}
	if err := db.ApplyMessageAction(1, []int64{first}, "restore", 0); err != nil {
		t.Fatal(err)
	}
	restored, _ := db.GetIMAPMessageState(1, first)
	if restored.FolderID != inbox.ID || restored.UID != 3 {
		t.Fatalf("restored state = %#v; destination UID must not be reused", restored)
	}
	mailbox, _ = db.GetIMAPMailboxState(1, inbox.ID)
	if mailbox.UIDNext != 4 {
		t.Fatalf("UIDNEXT=%d; want 4", mailbox.UIDNext)
	}
}

func TestIMAPModSeqTracksWebmailFlags(t *testing.T) {
	db := openIMAPTestDB(t)
	inbox, _ := db.GetFolderByType(1, "inbox")
	id, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "flags", Direction: "inbound", ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := db.GetIMAPMessageState(1, id)
	if err := db.MarkRead(id); err != nil {
		t.Fatal(err)
	}
	afterRead, _ := db.GetIMAPMessageState(1, id)
	if afterRead.ModSeq <= before.ModSeq {
		t.Fatalf("modseq did not advance after Seen: %d -> %d", before.ModSeq, afterRead.ModSeq)
	}
	if err := db.MarkStarred(id, true); err != nil {
		t.Fatal(err)
	}
	afterFlagged, _ := db.GetIMAPMessageState(1, id)
	if afterFlagged.ModSeq <= afterRead.ModSeq {
		t.Fatalf("modseq did not advance after Flagged: %d -> %d", afterRead.ModSeq, afterFlagged.ModSeq)
	}
}

func TestIMAPStateIsAccountScoped(t *testing.T) {
	db := openIMAPTestDB(t)
	inbox, _ := db.GetFolderByType(1, "inbox")
	id, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "owned", Direction: "inbound", ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if state, err := db.GetIMAPMessageState(2, id); err != nil || state != nil {
		t.Fatalf("other account state = %#v, %v; want nil", state, err)
	}
	if state, err := db.GetIMAPMailboxState(2, inbox.ID); err != nil || state != nil {
		t.Fatalf("other account mailbox = %#v, %v; want nil", state, err)
	}
}

func TestIMAPCustomMailboxLifecycle(t *testing.T) {
	db := openIMAPTestDB(t)
	folder, err := db.CreateIMAPFolder(1, "Projects/GoMail")
	if err != nil {
		t.Fatal(err)
	}
	state, err := db.GetIMAPMailboxState(1, folder.ID)
	if err != nil || state == nil || state.UIDValidity == 0 {
		t.Fatalf("mailbox state=%#v err=%v", state, err)
	}
	if err := db.RenameIMAPFolder(1, folder.ID, "Projects/Archive"); err != nil {
		t.Fatal(err)
	}
	renamed, _ := db.GetFolderByID(folder.ID)
	if renamed == nil || renamed.Name != "Projects/Archive" {
		t.Fatalf("renamed=%#v", renamed)
	}
	if err := db.DeleteIMAPFolder(1, folder.ID); err != nil {
		t.Fatal(err)
	}
	if deleted, _ := db.GetFolderByID(folder.ID); deleted != nil {
		t.Fatalf("folder remains: %#v", deleted)
	}
	for _, name := range []string{"", "INBOX", "a//b", "../escape", "line\nbreak"} {
		if _, err := db.CreateIMAPFolder(1, name); err == nil {
			t.Fatalf("accepted invalid mailbox %q", name)
		}
	}
	inbox, _ := db.GetFolderByType(1, "inbox")
	if err := db.DeleteIMAPFolder(1, inbox.ID); err == nil {
		t.Fatal("deleted protected Inbox")
	}
}

func TestIMAPRenameHierarchyAndInbox(t *testing.T) {
	db := openIMAPTestDB(t)
	parent, err := db.CreateIMAPFolder(1, "Projects")
	if err != nil {
		t.Fatal(err)
	}
	child, err := db.CreateIMAPFolder(1, "Projects/GoMail")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RenameIMAPFolder(1, parent.ID, "Work"); err != nil {
		t.Fatal(err)
	}
	renamedChild, _ := db.GetFolderByID(child.ID)
	if renamedChild == nil || renamedChild.Name != "Work/GoMail" {
		t.Fatalf("renamed child=%#v", renamedChild)
	}
	if err := db.DeleteIMAPFolder(1, parent.ID); err == nil {
		t.Fatal("deleted mailbox with children")
	}

	inbox, _ := db.GetFolderByType(1, "inbox")
	messageID, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "inbox-rename", Direction: "inbound", ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := db.GetIMAPMessageState(1, messageID)
	if err := db.RenameIMAPFolder(1, inbox.ID, "Old Inbox"); err != nil {
		t.Fatal(err)
	}
	archived, _ := db.GetFolderByID(inbox.ID)
	if archived == nil || archived.Name != "Old Inbox" || archived.FolderType != "custom" || archived.IsDefault {
		t.Fatalf("renamed Inbox=%#v", archived)
	}
	after, _ := db.GetIMAPMessageState(1, messageID)
	if after == nil || after.FolderID != inbox.ID || after.UID != before.UID {
		t.Fatalf("message identity changed: before=%#v after=%#v", before, after)
	}
	newInbox, err := db.GetFolderByType(1, "inbox")
	if err != nil || newInbox.ID == inbox.ID {
		t.Fatalf("replacement Inbox=%#v err=%v", newInbox, err)
	}
	snapshot, _ := db.GetIMAPMailboxSnapshot(1, newInbox.ID)
	if snapshot.Exists != 0 {
		t.Fatalf("replacement Inbox not empty: %#v", snapshot)
	}
}

func TestIMAPRecentIsClaimedOnce(t *testing.T) {
	db := openIMAPTestDB(t)
	inbox, _ := db.GetFolderByType(1, "inbox")
	id, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "recent", Direction: "inbound", ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	first, err := db.OpenIMAPMailbox(1, inbox.ID)
	if err != nil || first.Recent != 1 || len(first.RecentIDs) != 1 || first.RecentIDs[0] != id {
		t.Fatalf("first claim=%#v err=%v", first, err)
	}
	second, err := db.OpenIMAPMailbox(1, inbox.ID)
	if err != nil || second.Recent != 0 || len(second.RecentIDs) != 0 {
		t.Fatalf("second claim=%#v err=%v", second, err)
	}
}
