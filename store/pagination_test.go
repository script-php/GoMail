package store

import (
	"testing"
	"time"
)

func TestMessageKeysetPaginationStableAcrossInsert(t *testing.T) {
	db := mailboxDB(t)
	inbox, _ := db.GetFolderByType(1, "inbox")
	stamp := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var ids []int64
	for index := 0; index < 5; index++ {
		id, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "page", Direction: "inbound", Subject: "page", ReceivedAt: stamp})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	first, err := db.ListMessagesPage(1, "inbound", 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertMessageIDs(t, first.Messages, ids[4], ids[3])
	if !first.HasOlder || first.HasNewer {
		t.Fatalf("unexpected first-page navigation: %+v", first)
	}
	newID, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "new", Direction: "inbound", Subject: "new", ReceivedAt: stamp})
	if err != nil {
		t.Fatal(err)
	}
	older, err := db.ListMessagesPage(1, "inbound", 2, &MessageCursor{ReceivedAt: first.Messages[1].ReceivedAt, ID: first.Messages[1].ID, Direction: "older"})
	if err != nil {
		t.Fatal(err)
	}
	assertMessageIDs(t, older.Messages, ids[2], ids[1])
	if !older.HasNewer || !older.HasOlder {
		t.Fatalf("unexpected middle-page navigation: %+v", older)
	}
	newer, err := db.ListMessagesPage(1, "inbound", 2, &MessageCursor{ReceivedAt: older.Messages[0].ReceivedAt, ID: older.Messages[0].ID, Direction: "newer"})
	if err != nil {
		t.Fatal(err)
	}
	assertMessageIDs(t, newer.Messages, ids[4], ids[3])
	if !newer.HasNewer || !newer.HasOlder {
		t.Fatalf("new arrival should remain on a separate newer page: %+v newID=%d", newer, newID)
	}
}

func TestFolderAndSearchKeysetRemainAccountScoped(t *testing.T) {
	db := mailboxDB(t)
	inbox1, _ := db.GetFolderByType(1, "inbox")
	inbox2, _ := db.GetFolderByType(2, "inbox")
	stamp := time.Now().UTC().Truncate(time.Second)
	owned, _ := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox1.ID, MessageID: "owned", Direction: "inbound", Subject: "needle", ReceivedAt: stamp})
	_, _ = db.SaveMessage(&Message{AccountID: 2, FolderID: &inbox2.ID, MessageID: "private", Direction: "inbound", Subject: "needle", ReceivedAt: stamp})
	page, err := db.ListFolderMessagesPage(1, inbox2.ID, 50, nil)
	if err != nil || len(page.Messages) != 0 {
		t.Fatalf("cross-account folder listing leaked messages: %+v err=%v", page.Messages, err)
	}
	search, total, err := db.SearchMessagesPage(1, "needle", 50, nil)
	if err != nil || total != 1 {
		t.Fatalf("scoped search total=%d err=%v", total, err)
	}
	assertMessageIDs(t, search.Messages, owned)
}

func TestStarredMessagesPageScopedAndExcludesTrash(t *testing.T) {
	db := mailboxDB(t)
	inbox1, _ := db.GetFolderByType(1, "inbox")
	sent1, _ := db.GetFolderByType(1, "sent")
	inbox2, _ := db.GetFolderByType(2, "inbox")
	stamp := time.Now().UTC().Truncate(time.Second)
	inbound, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox1.ID, MessageID: "star-in", Direction: "inbound", IsStarred: true, ReceivedAt: stamp})
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := db.SaveMessage(&Message{AccountID: 1, FolderID: &sent1.ID, MessageID: "star-out", Direction: "outbound", IsStarred: true, ReceivedAt: stamp.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.SaveMessage(&Message{AccountID: 1, FolderID: &inbox1.ID, MessageID: "not-starred", Direction: "inbound", ReceivedAt: stamp.Add(2 * time.Second)})
	_, _ = db.SaveMessage(&Message{AccountID: 2, FolderID: &inbox2.ID, MessageID: "private-star", Direction: "inbound", IsStarred: true, ReceivedAt: stamp.Add(3 * time.Second)})
	page, err := db.ListStarredMessagesPage(1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertMessageIDs(t, page.Messages, outbound)
	if !page.HasOlder {
		t.Fatal("missing older starred page")
	}
	older, err := db.ListStarredMessagesPage(1, 1, &MessageCursor{ReceivedAt: page.Messages[0].ReceivedAt, ID: outbound, Direction: "older"})
	if err != nil {
		t.Fatal(err)
	}
	assertMessageIDs(t, older.Messages, inbound)
	if err := db.DeleteMessage(inbound); err != nil {
		t.Fatal(err)
	}
	count, err := db.CountStarredMessages(1)
	if err != nil || count != 1 {
		t.Fatalf("starred count=%d err=%v", count, err)
	}
}

func assertMessageIDs(t *testing.T, messages []*Message, expected ...int64) {
	t.Helper()
	if len(messages) != len(expected) {
		t.Fatalf("got %d messages, want %d", len(messages), len(expected))
	}
	for index := range expected {
		if messages[index].ID != expected[index] {
			t.Fatalf("message %d id=%d, want %d", index, messages[index].ID, expected[index])
		}
	}
}
