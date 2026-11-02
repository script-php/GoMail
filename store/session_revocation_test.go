package store

import (
	"testing"
	"time"
)

func TestPasswordUpdatesRevokeOnlyOwningWebSessions(t *testing.T) {
	root := t.TempDir()
	db, err := Open(root+"/mail.db", root+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.com'); INSERT INTO accounts(id,domain_id,email,password_hash,is_active) VALUES(1,1,'alice@example.com','old',1),(2,1,'bob@example.com','old',1)`); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	for token, email := range map[string]string{"alice-1": "alice@example.com", "alice-2": "alice@example.com", "bob": "bob@example.com"} {
		if err := db.SaveSession(token, email, expires); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.UpdateAccountPassword(1, "new"); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"alice-1", "alice-2"} {
		if got, err := db.GetSession(token); err != nil || got != "" {
			t.Fatalf("session %s survived password update: %q, %v", token, got, err)
		}
	}
	if got, err := db.GetSession("bob"); err != nil || got != "bob@example.com" {
		t.Fatalf("unrelated session changed: %q, %v", got, err)
	}
	if err := db.SaveSession("alice-3", "alice@example.com", expires); err != nil {
		t.Fatal(err)
	}
	account, err := db.GetAccount(1)
	if err != nil {
		t.Fatal(err)
	}
	account.Email = "alice-renamed@example.com"
	if err := db.UpdateAccountWithPassword(account, "admin-new"); err != nil {
		t.Fatal(err)
	}
	if got, err := db.GetSession("alice-3"); err != nil || got != "" {
		t.Fatalf("pre-rename session survived admin password update: %q, %v", got, err)
	}
}
