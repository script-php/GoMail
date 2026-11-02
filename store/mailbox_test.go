package store

import (
	"database/sql"
	"fmt"
	"testing"
	"time"
)

func mailboxDB(t *testing.T) *DB {
	t.Helper()
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { conn.Close() })
	if _, err := conn.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}
	db := &DB{DB: conn}
	if _, err := db.Exec(`INSERT INTO domains (id, domain) VALUES (1, 'drafts.example')`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{1, 2} {
		if _, err := db.Exec(`INSERT INTO accounts (id, domain_id, email, password_hash) VALUES (?, 1, ?, 'test')`, id, fmt.Sprintf("user%d@drafts.example", id)); err != nil {
			t.Fatal(err)
		}
		if err := db.DefaultFolders(id); err != nil {
			t.Fatal(err)
		}
	}
	return db
}
func mailboxMessage(t *testing.T, db *DB, owner int64, subject string) int64 {
	t.Helper()
	folder, err := db.GetFolderByType(owner, "inbox")
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.SaveMessage(&Message{AccountID: owner, FolderID: &folder.ID, MessageID: subject, Direction: "inbound", Subject: subject, ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func TestMailboxActionsIsolationAndRestore(t *testing.T) {
	db := mailboxDB(t)
	own := mailboxMessage(t, db, 1, "own")
	other := mailboxMessage(t, db, 2, "private")
	if err := db.ApplyMessageAction(1, []int64{own, other}, "trash", 0); err == nil {
		t.Fatal("cross-account batch accepted")
	}
	msg, _ := db.GetMessage(own, 1)
	if msg.IsDeleted {
		t.Fatal("failed batch changed own message")
	}
	foreignFolder, _ := db.GetFolderByType(2, "inbox")
	if err := db.ApplyMessageAction(1, []int64{own}, "move", foreignFolder.ID); err == nil {
		t.Fatal("foreign destination accepted")
	}
	for _, action := range []string{"read", "unread", "trash", "restore"} {
		if err := db.ApplyMessageAction(1, []int64{own}, action, 0); err != nil {
			t.Fatal(err)
		}
		msg, _ = db.GetMessage(own, 1)
		if msg.IsDeleted != (action == "trash") {
			t.Fatalf("wrong deletion state after %s", action)
		}
	}
	inbox, _ := db.GetFolderByType(1, "inbox")
	trash, _ := db.GetFolderByType(1, "trash")
	if inbox.TotalCount != 1 || inbox.UnreadCount != 1 || trash.TotalCount != 0 {
		t.Fatal("folder counts inconsistent")
	}
}

func TestMailboxMovementRules(t *testing.T) {
	db := mailboxDB(t)
	inbox, _ := db.GetFolderByType(1, "inbox")
	sent, _ := db.GetFolderByType(1, "sent")
	drafts, _ := db.GetFolderByType(1, "drafts")
	spam, _ := db.GetFolderByType(1, "spam")
	trash, _ := db.GetFolderByType(1, "trash")
	received := mailboxMessage(t, db, 1, "received")
	sentID, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &sent.ID, MessageID: "sent", Direction: "outbound", ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ id, target int64 }{{sentID, inbox.ID}, {received, sent.ID}, {received, drafts.ID}, {sentID, drafts.ID}} {
		if err := db.ApplyMessageAction(1, []int64{tc.id}, "move", tc.target); err == nil {
			t.Fatalf("forbidden move of %d succeeded", tc.id)
		}
	}
	if err := db.ApplyMessageAction(1, []int64{received, sentID}, "move", spam.ID); err == nil {
		t.Fatal("mixed invalid batch succeeded")
	}
	if msg, _ := db.GetMessage(received, 1); msg.FolderID == nil || *msg.FolderID != inbox.ID {
		t.Fatal("failed batch moved received message")
	}
	if err := db.ApplyMessageAction(1, []int64{received}, "move", spam.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyMessageAction(1, []int64{received}, "move", spam.ID); err == nil {
		t.Fatal("same-folder Spam move succeeded")
	}
	if err := db.ApplyMessageAction(1, []int64{received}, "move", inbox.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyMessageAction(1, []int64{sentID}, "trash", 0); err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyMessageAction(1, []int64{sentID}, "move", inbox.ID); err == nil {
		t.Fatal("moved a trashed sent message to Inbox")
	}
	if msg, _ := db.GetMessage(sentID, 1); msg.FolderID == nil || *msg.FolderID != trash.ID {
		t.Fatal("sent message left Trash")
	}
	if err := db.ApplyMessageAction(1, []int64{sentID}, "restore", 0); err != nil {
		t.Fatal(err)
	}
	if msg, _ := db.GetMessage(sentID, 1); msg.FolderID == nil || *msg.FolderID != sent.ID {
		t.Fatal("sent message did not restore to Sent")
	}
}
func TestSearchOwnershipAndLiteralWildcards(t *testing.T) {
	db := mailboxDB(t)
	mailboxMessage(t, db, 1, "discount 10%_today")
	mailboxMessage(t, db, 2, "discount 10%_today")
	deleted := mailboxMessage(t, db, 1, "discount 10%_today deleted")
	if err := db.ApplyMessageAction(1, []int64{deleted}, "trash", 0); err != nil {
		t.Fatal(err)
	}
	page, total, err := db.SearchMessagesPage(1, "%_", 50, nil)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(page.Messages) != 1 {
		t.Fatalf("search leaked or mismatched messages: %d", total)
	}
	_, total, err = db.SearchMessagesPage(1, "' OR 1=1 --", 50, nil)
	if err != nil || total != 0 {
		t.Fatalf("SQL input not literal: total=%d err=%v", total, err)
	}
}
func TestQueueInsertionRollsBackAllRecipients(t *testing.T) {
	db := mailboxDB(t)
	// SQLite triggers are not supported on MySQL, skip this test
	if db.IsMySQL() {
		t.Skip("SQLite triggers not available on MySQL backend")
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_recipient BEFORE INSERT ON outbound_queue WHEN NEW.rcpt_to = 'reject@example.com' BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	msg := &Message{AccountID: 1, MessageID: "queued", Direction: "outbound", ReceivedAt: time.Now()}
	entries := []*QueueEntry{{RcptTo: "ok@example.com", RawMessage: []byte("mail")}, {RcptTo: "reject@example.com", RawMessage: []byte("mail")}}
	if _, err := db.SaveQueuedMessage(msg, entries); err == nil {
		t.Fatal("expected failure")
	}
	for _, table := range []string{"messages", "outbound_queue"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s: partial commit", table)
		}
	}
	entries = entries[:1]
	if _, err := db.SaveQueuedMessage(msg, entries); err != nil {
		t.Fatal(err)
	}
}

func TestQueueStateTransitionIsCompareAndSet(t *testing.T) {
	db := mailboxDB(t)
	id, err := db.EnqueueMessage(&QueueEntry{MailFrom: "a@example.com", RcptTo: "b@example.net", RawMessage: []byte("mail"), MaxAttempts: 3, NextRetry: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.TransitionQueueEntry(id, "pending", "sending", 0, time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	if err := db.TransitionQueueEntry(id, "pending", "sent", 1, time.Now(), ""); err == nil {
		t.Fatal("stale worker overwrote queue state")
	}
	if err := db.TransitionQueueEntry(id, "sending", "sent", 1, time.Now(), ""); err != nil {
		t.Fatal(err)
	}
}

func TestAttachmentMetadataBatchRollsBack(t *testing.T) {
	db := mailboxDB(t)
	messageID := mailboxMessage(t, db, 1, "attachments")
	if _, err := db.Exec(`CREATE TRIGGER reject_attachment BEFORE INSERT ON attachments WHEN NEW.filename = 'reject' BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	err := db.SaveAttachments([]*Attachment{
		{MessageID: messageID, Filename: "first", StoragePath: "first.bin"},
		{MessageID: messageID, Filename: "reject", StoragePath: "reject.bin"},
	})
	if err == nil {
		t.Fatal("attachment batch unexpectedly succeeded")
	}
	attachments, err := db.GetAttachments(messageID)
	if err != nil || len(attachments) != 0 {
		t.Fatalf("partial attachment metadata survived: %+v %v", attachments, err)
	}
}
