package smtp

import (
	"path/filepath"
	"strings"
	"testing"

	"gomail/config"
	"gomail/store"
)

func TestDataDoesNotAcceptRecipientDisabledAfterRCPT(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "alice@example.test", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE accounts SET is_active=0 WHERE id=?`, accountID); err != nil {
		t.Fatal(err)
	}
	sess := &Session{mailFrom: "sender@localhost", rcptTo: []string{"alice@example.test"}, clientIP: "127.0.0.1", ehlo: "localhost"}
	sess.data.WriteString("From: sender@localhost\r\nTo: alice@example.test\r\nSubject: test\r\n\r\nbody\r\n")
	inbound := &InboundServer{cfg: &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test", Domain: "example.test"}}, db: db}
	if err := inbound.processMessage(sess); err == nil || !strings.Contains(err.Error(), "became unavailable") {
		t.Fatalf("disabled recipient was accepted: %v", err)
	}
}
