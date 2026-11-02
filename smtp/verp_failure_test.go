package smtp

import (
	"path/filepath"
	"strings"
	"testing"

	"gomail/config"
	"gomail/store"
)

func TestVERPBounceStoreFailureDefersAcceptance(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.test'); INSERT INTO accounts(id,domain_id,email,password_hash,is_active) VALUES(1,1,'sender@example.test','unused',1)`); err != nil {
		t.Fatal(err)
	}
	verp, err := db.EncodeVERP("sender@example.test", "recipient@remote.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO outbound_queue(mail_from,rcpt_to,raw_message,verp_bounce_address) VALUES(?,?,?,?)`, "sender@example.test", "recipient@remote.test", []byte("Subject: sent\r\n\r\nbody"), verp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_verp BEFORE INSERT ON verp_bounces BEGIN SELECT RAISE(FAIL, 'bounce unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	sess := &Session{mailFrom: "", rcptTo: []string{verp}, clientIP: "127.0.0.1", ehlo: "remote.test"}
	sess.data.WriteString("From: postmaster@remote.test\r\nTo: " + verp + "\r\nSubject: Delivery failed\r\n\r\nMailbox unavailable\r\n")
	inbound := &InboundServer{cfg: &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test", Domain: "example.test"}}, db: db}
	if err := inbound.processMessage(sess); err == nil || !strings.Contains(err.Error(), "recording VERP bounce") {
		t.Fatalf("bounce store failure accepted: %v", err)
	}
}
