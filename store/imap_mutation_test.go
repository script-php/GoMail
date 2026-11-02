package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIMAPCopyMoveAndExpungePreserveResources(t *testing.T) {
	db := openIMAPTestDB(t)
	inbox, _ := db.GetFolderByType(1, "inbox")
	archive, err := db.CreateIMAPFolder(1, "Archive")
	if err != nil {
		t.Fatal(err)
	}
	trash, _ := db.GetFolderByType(1, "trash")
	originalID, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "copy-source", Direction: "inbound", RawMessage: []byte("Subject: copy\r\n\r\nbody"), Size: 25, IsRead: true, ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	originalPath := filepath.Join(db.AttachmentsPath(), "original.bin")
	if err := os.WriteFile(originalPath, []byte("attachment"), 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveAttachment(&Attachment{MessageID: originalID, Filename: "original.bin", ContentType: "application/octet-stream", Size: 10, StoragePath: "original.bin"}); err != nil {
		t.Fatal(err)
	}
	pairs, err := db.CopyIMAPMessages(1, inbox.ID, archive.ID, []int64{originalID})
	if err != nil || len(pairs) != 1 || pairs[0].Source != 1 || pairs[0].Destination != 1 {
		t.Fatalf("copy pairs=%#v err=%v", pairs, err)
	}
	sentRefs, _ := db.ListIMAPMessageRefs(1, archive.ID)
	if len(sentRefs) != 1 {
		t.Fatalf("sent refs=%#v", sentRefs)
	}
	copiedID := sentRefs[0].MessageID
	attachments, err := db.GetAttachments(copiedID)
	if err != nil || len(attachments) != 1 || attachments[0].StoragePath == "original.bin" {
		t.Fatalf("copied attachments=%#v err=%v", attachments, err)
	}
	copiedPath, ok := db.safeAttachmentPath(attachments[0].StoragePath)
	if !ok {
		t.Fatal("unsafe copied attachment path")
	}
	if data, err := os.ReadFile(copiedPath); err != nil || string(data) != "attachment" {
		t.Fatalf("copied attachment=%q err=%v", data, err)
	}
	deleted := true
	if err := db.UpdateIMAPFlags(1, archive.ID, []int64{copiedID}, IMAPFlagMutation{Mode: "add", Deleted: &deleted}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExpungeIMAPMessages(1, archive.ID, []int64{copiedID}); err != nil {
		t.Fatal(err)
	}
	expunges, err := db.GetIMAPExpunges(1, archive.ID, 0)
	if err != nil || len(expunges) != 1 || expunges[0].UID != 1 || expunges[0].ModSeq == 0 {
		t.Fatalf("expunge history=%#v err=%v", expunges, err)
	}
	if _, err := os.Stat(copiedPath); !os.IsNotExist(err) {
		t.Fatalf("copied attachment remains after expunge: %v", err)
	}
	if _, err := os.Stat(originalPath); err != nil {
		t.Fatalf("source attachment was removed: %v", err)
	}
	pairs, err = db.MoveIMAPMessages(1, inbox.ID, trash.ID, []int64{originalID})
	if err != nil || len(pairs) != 1 || pairs[0].Destination != 1 {
		t.Fatalf("move pairs=%#v err=%v", pairs, err)
	}
	moved, _ := db.GetMessage(originalID, 1)
	state, _ := db.GetIMAPMessageState(1, originalID)
	if moved.FolderID == nil || *moved.FolderID != trash.ID || !moved.IsDeleted || state.FolderID != trash.ID {
		t.Fatalf("moved message=%#v state=%#v", moved, state)
	}
	expunges, err = db.GetIMAPExpunges(1, inbox.ID, 0)
	if err != nil || len(expunges) != 1 || expunges[0].UID != pairs[0].Source {
		t.Fatalf("move expunge history=%#v err=%v", expunges, err)
	}
}

func TestIMAPCannotMoveOrCopyMessagesIntoDrafts(t *testing.T) {
	db := openIMAPTestDB(t)
	inbox, _ := db.GetFolderByType(1, "inbox")
	drafts, _ := db.GetFolderByType(1, "drafts")
	id, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "received-to-drafts", Direction: "inbound", ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CopyIMAPMessages(1, inbox.ID, drafts.ID, []int64{id}); err == nil {
		t.Fatal("IMAP COPY into Drafts succeeded")
	}
	if _, err := db.MoveIMAPMessages(1, inbox.ID, drafts.ID, []int64{id}); err == nil {
		t.Fatal("IMAP MOVE into Drafts succeeded")
	}
	if msg, _ := db.GetMessage(id, 1); msg.FolderID == nil || *msg.FolderID != inbox.ID {
		t.Fatal("rejected IMAP move changed source folder")
	}
	if refs, err := db.ListIMAPMessageRefs(1, drafts.ID); err != nil || len(refs) != 0 {
		t.Fatalf("Drafts refs=%v err=%v", refs, err)
	}
}

func TestIMAPSameMailboxCopyAndMove(t *testing.T) {
	db := openIMAPTestDB(t)
	inbox, _ := db.GetFolderByType(1, "inbox")
	id, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "same-mailbox", Direction: "inbound", ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	copyPairs, err := db.CopyIMAPMessages(1, inbox.ID, inbox.ID, []int64{id})
	if err != nil || len(copyPairs) != 1 || copyPairs[0].Destination == copyPairs[0].Source {
		t.Fatalf("same-mailbox COPY pairs=%v err=%v", copyPairs, err)
	}
	movePairs, err := db.MoveIMAPMessages(1, inbox.ID, inbox.ID, []int64{id})
	if err != nil || len(movePairs) != 1 || movePairs[0].Destination == movePairs[0].Source {
		t.Fatalf("same-mailbox MOVE pairs=%v err=%v", movePairs, err)
	}
}
