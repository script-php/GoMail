package smtp

import (
	"path/filepath"
	"testing"

	"gomail/config"
	"gomail/store"
)

func TestOrdinaryDSNDeliveredWithoutTrustedBounceRecord(t *testing.T) {
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
	if _, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "alice@example.test", PasswordHash: "unused", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	sess := &Session{mailFrom: "", rcptTo: []string{"alice@example.test"}, clientIP: "127.0.0.1", ehlo: "remote.test"}
	sess.data.WriteString("From: forged@example.test\r\nTo: alice@example.test\r\nSubject: Delivery Status Notification\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; remote.test\r\n\r\nFinal-Recipient: rfc822; victim@remote.test\r\nAction: failed\r\nStatus: 5.1.1\r\nDiagnostic-Code: smtp; 550 forged\r\n")
	inbound := &InboundServer{cfg: &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test", Domain: "example.test"}}, db: db}
	if err := inbound.processMessage(sess); err != nil {
		t.Fatal(err)
	}
	var bounces, messages int
	if err := db.QueryRow(`SELECT COUNT(*) FROM verp_bounces`).Scan(&bounces); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE account_id=1`).Scan(&messages); err != nil {
		t.Fatal(err)
	}
	if bounces != 0 || messages != 1 {
		t.Fatalf("unverified DSN outcome: bounces=%d messages=%d", bounces, messages)
	}
}
