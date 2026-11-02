package smtp

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"gomail/config"
	"gomail/store"
)

func TestInboundAcceptsOnlyIssuedVERPBounceAddress(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(root+"/mail.db", root+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.com'); INSERT INTO accounts(id,domain_id,email,password_hash,is_active) VALUES(1,1,'sender@example.com','test',1)`); err != nil {
		t.Fatal(err)
	}
	recipient := "user+tag=notice@north-west.example.net"
	verp, err := db.EncodeVERP("sender@example.com", recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO outbound_queue(mail_from,rcpt_to,raw_message,verp_bounce_address) VALUES(?,?,?,?)`, "sender@example.com", recipient, []byte("Subject: original\r\n\r\nbody"), verp); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Server.Hostname = "mail.example.com"
	inbound := &InboundServer{cfg: cfg, db: db, rateLimiter: NewRateLimiter(100, 100)}
	server, client := net.Pipe()
	defer client.Close()
	sess := NewSession(server, cfg.Server.Hostname, []string{"example.com"}, func(email string) (bool, error) { return email == "sender@example.com", nil }, nil, 1024*1024, 10, 2*time.Second, 2*time.Second, "", false, db)
	done := make(chan struct{})
	go func() { inbound.runSession(sess); close(done) }()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(client)
	read := func(prefix string) {
		t.Helper()
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, prefix) {
			t.Fatalf("SMTP response %q (%v), want %q", line, err, prefix)
		}
	}
	send := func(command string) {
		t.Helper()
		if _, err := fmt.Fprintf(client, "%s\r\n", command); err != nil {
			t.Fatal(err)
		}
	}
	read("220 ")
	send("HELO remote.example.net")
	read("250 ")
	send("MAIL FROM:<>")
	read("250 ")
	send("RCPT TO:<sender+v1-unknown@example.com>")
	read("550 5.1.1 ")
	send("RCPT TO:<" + verp + ">")
	read("250 2.1.5 ")
	send("DATA")
	read("354 ")
	send("From: postmaster@remote.example.net")
	send("To: " + verp)
	send("Subject: Delivery failed")
	send("")
	send("Mailbox unavailable")
	send(".")
	read("250 ")
	var recorded, senderEmail string
	if err := db.QueryRow(`SELECT original_recipient, sender_email FROM verp_bounces WHERE bounce_address = ?`, verp).Scan(&recorded, &senderEmail); err != nil || recorded != recipient || senderEmail != "sender@example.com" {
		t.Fatalf("bounce recipient = %q, sender = %q, err = %v", recorded, senderEmail, err)
	}
	send("QUIT")
	read("221 ")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SMTP session did not exit")
	}
}
