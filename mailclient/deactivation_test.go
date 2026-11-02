package mailclient

import (
	"bufio"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"gomail/config"
	"gomail/store"
)

func TestActiveIMAPAndPOP3SessionsCloseAfterAccountDeactivation(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.com'); INSERT INTO accounts(id,domain_id,email,password_hash,is_active) VALUES(1,1,'user@example.com',?,1)`, string(hash)); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Clients: config.MailClientsConfig{ReadTimeout: 5, WriteTimeout: 5, MaxConnections: 2, AuthAttempts: 10}}
	server := NewServer(cfg, db, nil, nil)
	for _, tc := range []struct {
		name, login, next, success, closed string
		handler                            func(net.Conn)
	}{
		{"imap", "a1 LOGIN user@example.com password", "a2 NOOP", "a1 OK", "* BYE account no longer active", server.handleIMAP},
		{"pop3", "PASS password", "STAT", "+OK maildrop", "-ERR account no longer active", server.handlePOP3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.Exec(`UPDATE accounts SET is_active = 1 WHERE id = 1`); err != nil {
				t.Fatal(err)
			}
			side, client := net.Pipe()
			defer client.Close()
			go tc.handler(side)
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(client)
			if _, err := reader.ReadString('\n'); err != nil {
				t.Fatal(err)
			}
			if tc.name == "pop3" {
				_, _ = fmt.Fprint(client, "USER user@example.com\r\n")
				if _, err := reader.ReadString('\n'); err != nil {
					t.Fatal(err)
				}
			}
			_, _ = fmt.Fprintf(client, "%s\r\n", tc.login)
			response, err := reader.ReadString('\n')
			if err != nil || !strings.Contains(response, tc.success) {
				t.Fatalf("login response %q, err %v", response, err)
			}
			if _, err := db.Exec(`UPDATE accounts SET is_active = 0 WHERE id = 1`); err != nil {
				t.Fatal(err)
			}
			_, _ = fmt.Fprintf(client, "%s\r\n", tc.next)
			response, err = reader.ReadString('\n')
			if err != nil || !strings.Contains(response, tc.closed) {
				t.Fatalf("deactivation response %q, err %v", response, err)
			}
			if _, err := reader.ReadString('\n'); err == nil {
				t.Fatal("deactivated session remained open")
			}
		})
	}
}

func TestSubmissionRejectsCompletedDATAAfterDeactivation(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.com'); INSERT INTO accounts(id,domain_id,email,password_hash,is_active) VALUES(1,1,'user@example.com','x',0)`); err != nil {
		t.Fatal(err)
	}
	server := NewServer(&config.Config{Server: config.ServerConfig{Hostname: "mail.example.com"}, SMTP: config.SMTPConfig{MaxMessageSize: 1024 * 1024}, Clients: config.MailClientsConfig{MaxConnections: 1, ReadTimeout: 5, WriteTimeout: 5}}, db, nil, nil)
	side, client := net.Pipe()
	defer side.Close()
	defer client.Close()
	p := &submissionSession{server: server, conn: side, reader: bufio.NewReader(side), writer: bufio.NewWriter(side), account: &store.Account{ID: 1, Email: "user@example.com"}, mailFrom: "user@example.com", recipients: []string{"other@example.net"}}
	done := make(chan struct{})
	go func() { p.handleDATA(); close(done) }()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(client)
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "354 ") {
		t.Fatalf("DATA response %q, %v", line, err)
	}
	_, _ = fmt.Fprint(client, "From: user@example.com\r\n\r\nbody\r\n.\r\n")
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "421 Account no longer active") {
		t.Fatalf("deactivation response %q, %v", line, err)
	}
	<-done
}
