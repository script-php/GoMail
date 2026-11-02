package mailclient

import (
	"bufio"
	"encoding/base64"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gomail/config"
	"gomail/store"
)

func TestAuthenticationStoreFailureIsTemporaryAndNotRateLimited(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(&config.Config{Clients: config.MailClientsConfig{AuthAttempts: 3, ReadTimeout: 1, WriteTimeout: 1}}, db, nil, nil)
	for _, tc := range []struct {
		name string
		want string
		run  func(net.Conn)
	}{
		{"submission", "454 4.3.0", func(conn net.Conn) {
			p := &submissionSession{server: srv, conn: conn, writer: bufio.NewWriter(conn), tls: true, ehlo: true}
			credentials := base64.StdEncoding.EncodeToString([]byte("\x00alice@example.test\x00password"))
			p.authenticate("PLAIN " + credentials)
		}},
		{"imap", "a1 NO [UNAVAILABLE]", func(conn net.Conn) {
			s := &imapSession{server: srv, conn: conn, writer: bufio.NewWriter(conn)}
			s.finishAuthentication("a1", "alice@example.test", "password")
		}},
		{"pop3", "-ERR authentication temporarily unavailable", func(conn net.Conn) {
			p := &pop3Session{server: srv, conn: conn, writer: bufio.NewWriter(conn), username: "alice@example.test"}
			p.authorization("PASS", "password")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			done := make(chan struct{})
			go func() { tc.run(server); close(done) }()
			_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
			reply, err := bufio.NewReader(client).ReadString('\n')
			if err != nil || !strings.HasPrefix(reply, tc.want) {
				t.Fatalf("authentication reply=%q err=%v", reply, err)
			}
			<-done
			if len(srv.auth) != 0 {
				t.Fatalf("database outage counted as bad password: %+v", srv.auth)
			}
		})
	}
}
