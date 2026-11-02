package store

import (
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
