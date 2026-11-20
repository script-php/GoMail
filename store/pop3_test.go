package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestPOP3MaildropAndDelete(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "mail.db"), filepath.Join(t.TempDir(), "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&Domain{Domain: "example.com", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&Account{DomainID: domainID, Email: "user@example.com", PasswordHash: "hash", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	inbox, _ := db.GetFolderByType(accountID, "inbox")
	spam, _ := db.GetFolderByType(accountID, "spam")
	inboxID, err := db.SaveMessage(&Message{AccountID: accountID, FolderID: &inbox.ID, MessageID: "inbox", Direction: "inbound", RawMessage: []byte("Subject: inbox\r\n\r\nbody\r\n"), ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.SaveMessage(&Message{AccountID: accountID, FolderID: &spam.ID, MessageID: "spam", Direction: "inbound", RawMessage: []byte("spam"), ReceivedAt: time.Now()})

	messages, err := db.ListPOP3Messages(accountID)
	if err != nil || len(messages) != 1 || messages[0].ID != inboxID || messages[0].Octets != len("Subject: inbox\r\n\r\nbody\r\n") {
		t.Fatalf("maildrop=%+v err=%v", messages, err)
	}
	raw, err := db.GetPOP3MessageRaw(accountID, inboxID)
	if err != nil || string(raw) != "Subject: inbox\r\n\r\nbody\r\n" {
		t.Fatalf("on-demand POP3 body=%q err=%v", raw, err)
	}
	if err := db.DeletePOP3Messages(accountID, []int64{inboxID}); err != nil {
		t.Fatal(err)
	}
	messages, err = db.ListPOP3Messages(accountID)
	if err != nil || len(messages) != 0 {
		t.Fatalf("deleted message remained: %+v err=%v", messages, err)
	}
	message, err := db.GetMessage(inboxID, accountID)
	if err != nil || message == nil || !message.IsDeleted {
		t.Fatalf("message was not moved to trash: %+v err=%v", message, err)
	}
	updatedInbox, err := db.GetFolderByType(accountID, "inbox")
	if err != nil || updatedInbox.TotalCount != 0 {
		t.Fatalf("POP3 Inbox count: %+v, %v", updatedInbox, err)
	}
	updatedTrash, err := db.GetFolderByType(accountID, "trash")
	if err != nil || updatedTrash.TotalCount != 1 {
		t.Fatalf("POP3 Trash count: %+v, %v", updatedTrash, err)
	}
}

func TestPOP3SnapshotCannotReadOrDeleteMessageMovedOutOfInbox(t *testing.T) {
	db := mailboxDB(t)
	id := mailboxMessage(t, db, 1, "pop3-moved")
	inbox, err := db.GetFolderByType(1, "inbox")
	if err != nil {
		t.Fatal(err)
	}
	spam, err := db.GetFolderByType(1, "spam")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := db.ListPOP3Messages(1)
	if err != nil || len(snapshot) != 1 || snapshot[0].ID != id {
		t.Fatalf("POP3 snapshot=%+v err=%v", snapshot, err)
	}
	if _, err := db.MoveIMAPMessages(1, inbox.ID, spam.ID, []int64{id}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetPOP3MessageRaw(1, id); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("moved message still readable through POP3: %v", err)
	}
	if err := db.DeletePOP3Messages(1, []int64{id}); err == nil {
		t.Fatal("stale POP3 session deleted a message moved to Spam")
	}
	message, err := db.GetMessage(id, 1)
	if err != nil || message == nil || message.FolderID == nil || *message.FolderID != spam.ID || message.IsDeleted {
		t.Fatalf("moved message changed by stale POP3 delete: %+v err=%v", message, err)
	}
}

func TestPOP3DeleteRollsBackWhenFolderCountFails(t *testing.T) {
	db := mailboxDB(t)
	id := mailboxMessage(t, db, 1, "pop3-count-failure")
	if _, err := db.Exec(`CREATE TRIGGER fail_pop3_count BEFORE UPDATE OF total_count ON folders
		WHEN NEW.total_count > 0 BEGIN SELECT RAISE(FAIL, 'folder count unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.DeletePOP3Messages(1, []int64{id}); err == nil {
		t.Fatal("POP3 deletion committed without folder counts")
	}
	message, err := db.GetMessage(id, 1)
	if err != nil || message == nil || message.IsDeleted {
		t.Fatalf("failed POP3 deletion moved message: %+v, %v", message, err)
	}
}

func TestPOP3CanonicalOctets(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{
		{"", 0},
		{"line", len("line\r\n")},
		{"a\nb", len("a\r\nb\r\n")},
		{"a\rb", len("a\r\nb\r\n")},
		{"a\r\nb\r\n", len("a\r\nb\r\n")},
	} {
		if got := pop3CanonicalOctets([]byte(tc.raw)); got != tc.want {
			t.Errorf("octets(%q)=%d, want %d", tc.raw, got, tc.want)
		}
	}
}
