package smtp

import (
	"bufio"
	"fmt"
	"gomail/config"
	"gomail/store"
	"net"
	"strings"
	"testing"
	"time"
)

func TestEmptyDATAAndBDATReceiveFinalReply(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(root+"/mail.db", root+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.com'); INSERT INTO accounts(id,domain_id,email,password_hash,is_active) VALUES(1,1,'alice@example.com','test',1)`); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Server.Hostname = "mail.example.com"
	inbound := &InboundServer{cfg: cfg, db: db, rateLimiter: NewRateLimiter(100, 100)}
	server, client := net.Pipe()
	defer client.Close()
	sess := NewSession(server, cfg.Server.Hostname, []string{"example.com"}, func(email string) (bool, error) { return email == "alice@example.com", nil }, nil, 1024*1024, 10, 2*time.Second, 2*time.Second, "", false, db)
	done := make(chan struct{})
	go func() { inbound.runSession(sess); close(done) }()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(client)
	read := func(prefix string) {
		t.Helper()
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, prefix) {
			t.Fatalf("SMTP response got %q (%v), want prefix %q", line, err, prefix)
		}
	}
	send := func(command string) {
		t.Helper()
		if _, err := fmt.Fprintf(client, "%s\r\n", command); err != nil {
			t.Fatal(err)
		}
	}
	read("220 ")
	send("HELO sender.example.net")
	read("250 ")
	for _, transfer := range []string{"DATA", "BDAT 0 LAST"} {
		if transfer == "BDAT 0 LAST" {
			send("EHLO sender.example.net")
			for {
				line, err := reader.ReadString('\n')
				if err != nil || !strings.HasPrefix(line, "250") {
					t.Fatalf("EHLO response=%q err=%v", line, err)
				}
				if strings.HasPrefix(line, "250 ") {
					break
				}
			}
		}
		send("MAIL FROM:<sender@example.net>")
		read("250 ")
		send("RCPT TO:<alice@example.com>")
		read("250 ")
		send(transfer)
		if transfer == "DATA" {
			read("354 ")
			send(".")
		}
		read("554 5.6.0 ")
		send("NOOP")
		read("250 ")
	}
	send("QUIT")
	read("221 ")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SMTP session did not exit")
	}
}
