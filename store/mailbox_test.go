package store

import (
	"database/sql"
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
	for _, id := range []int64{1, 2} {
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
func TestSearchOwnershipAndLiteralWildcards(t *testing.T) {
	db := mailboxDB(t)
	mailboxMessage(t, db, 1, "discount 10%_today")
	mailboxMessage(t, db, 2, "discount 10%_today")
	deleted := mailboxMessage(t, db, 1, "discount 10%_today deleted")
	if err := db.ApplyMessageAction(1, []int64{deleted}, "trash", 0); err != nil {
		t.Fatal(err)
	}
	messages, total, err := db.SearchMessages(1, "%_", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(messages) != 1 {
		t.Fatalf("search leaked or mismatched messages: %d", total)
	}
	_, total, err = db.SearchMessages(1, "' OR 1=1 --", 50, 0)
	if err != nil || total != 0 {
		t.Fatalf("SQL input not literal: total=%d err=%v", total, err)
	}
}
func TestQueueInsertionRollsBackAllRecipients(t *testing.T) {
	db := mailboxDB(t)
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
