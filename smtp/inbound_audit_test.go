package smtp

import (
	"bufio"
	"crypto/tls"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gomail/config"
	"gomail/store"
)

func TestInboundSTARTTLSHandshakeTimesOut(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, writer: bufio.NewWriter(server), state: StateReady, esmtp: true,
		tlsConfig: &tls.Config{MinVersion: tls.VersionTLS12}, readTimeout: 100 * time.Millisecond, writeTimeout: time.Second}
	done := make(chan struct{})
	go func() { s.handleSTARTTLS(); close(done) }()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if line, err := bufio.NewReader(client).ReadString('\n'); err != nil || !strings.HasPrefix(line, "220 ") {
		t.Fatalf("STARTTLS reply=%q err=%v", line, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TLS handshake remained open past deadline")
	}
	if s.state != StateQuit {
		t.Fatalf("timed-out TLS session state=%d", s.state)
	}
}

func TestInboundMissingInboxDoesNotAcceptMessageOrRecordDMARCFeedback(t *testing.T) {
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
	if _, err := db.Exec(`DELETE FROM folders WHERE account_id = ? AND folder_type = 'inbox'`, accountID); err != nil {
		t.Fatal(err)
	}
	sess := &Session{mailFrom: "sender@localhost", rcptTo: []string{"alice@example.test"}, clientIP: "127.0.0.1", ehlo: "localhost"}
	sess.data.WriteString("From: sender@localhost\r\nTo: alice@example.test\r\nSubject: test\r\n\r\nbody\r\n")
	inbound := &InboundServer{cfg: &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test", Domain: "example.test"}}, db: db}
	if err := inbound.processMessage(sess); err == nil || !strings.Contains(err.Error(), "inbox folder missing") {
		t.Fatalf("missing Inbox accepted: %v", err)
	}
	var messages, feedback int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&messages); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM dmarc_feedback`).Scan(&feedback); err != nil {
		t.Fatal(err)
	}
	if messages != 0 || feedback != 0 {
		t.Fatalf("rejected delivery left messages=%d feedback=%d", messages, feedback)
	}
}

func TestInboundSuccessDSNDoesNotRequireDKIMKey(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	inbound := &InboundServer{cfg: &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test", Domain: "example.test"}}, db: db}
	report, err := inbound.prepareDeliveryDSN("sender@remote.test", "alice@example.test", "", "", []byte("From: sender@remote.test\r\n\r\nbody"))
	if err != nil || report == nil || len(report.RawMessage) == 0 || report.MailFrom != "" {
		t.Fatalf("unsigned success DSN unavailable: report=%+v err=%v", report, err)
	}
}

func TestInboundDuplicateRecipientDoesNotDuplicateDeliveryOrReplaceDSNOptions(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, writer: bufio.NewWriter(server), state: StateMail,
		mailFrom: "sender@remote.test", domains: []string{"example.test"}, esmtp: true,
		maxRcpt: 10, writeTimeout: time.Second, dsnNotify: make(map[string]string),
		dsnOriginalRcpt: make(map[string]string), accountExists: func(string) (bool, error) { return true, nil }}
	r := bufio.NewReader(client)
	for _, command := range []string{
		"TO:<alice@example.test> NOTIFY=SUCCESS",
		"TO:<alice@example.test> NOTIFY=FAILURE",
	} {
		done := make(chan struct{})
		go func() { s.handleRCPT(command); close(done) }()
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		if reply, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(reply, "250 ") {
			t.Fatalf("RCPT reply=%q err=%v", reply, err)
		}
		<-done
	}
	if len(s.rcptTo) != 1 || s.dsnNotify["alice@example.test"] != "SUCCESS" {
		t.Fatalf("duplicate recipient changed delivery state: rcpt=%v notify=%v", s.rcptTo, s.dsnNotify)
	}
}
