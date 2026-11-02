package mailclient

import (
	"bufio"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"gomail/config"
	"gomail/store"
)

func TestIMAPPlainAuthorizationIdentity(t *testing.T) {
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
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.test'); INSERT INTO accounts(id,domain_id,email,password_hash,is_active) VALUES(1,1,'user@example.test',?,1)`, string(hash)); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(&config.Config{Clients: config.MailClientsConfig{AuthAttempts: 10, WriteTimeout: 2}}, db, nil, nil)
	for _, tc := range []struct{ authzid, want string }{
		{"", "a1 OK "},
		{"USER@example.test", "a1 OK "},
		{"other@example.test", "a1 NO "},
	} {
		server, client := net.Pipe()
		session := &imapSession{server: srv, conn: server, writer: bufio.NewWriter(server)}
		done := make(chan struct{})
		go func() { session.finishAuthentication("a1", "user@example.test", "password", tc.authzid); close(done) }()
		_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
		reply, err := bufio.NewReader(client).ReadString('\n')
		if err != nil || !strings.HasPrefix(reply, tc.want) {
			t.Fatalf("authzid=%q response=%q err=%v", tc.authzid, reply, err)
		}
		<-done
		if (session.account != nil) != strings.Contains(tc.want, "OK") {
			t.Fatalf("authzid=%q account=%v", tc.authzid, session.account)
		}
		server.Close()
		client.Close()
	}
}
