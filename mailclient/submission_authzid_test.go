package mailclient

import (
	"bufio"
	"encoding/base64"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"gomail/config"
	"gomail/store"
)

func TestSubmissionPlainAuthorizationIdentity(t *testing.T) {
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
	srv := NewServer(&config.Config{Clients: config.MailClientsConfig{AuthAttempts: 10, ReadTimeout: 2, WriteTimeout: 2}}, db, nil, nil)
	for _, tc := range []struct{ name, authzid, want string }{
		{"derived", "", "235 "},
		{"same-account", "USER@example.com", "235 "},
		{"other-account", "other@example.com", "535 "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			p := &submissionSession{server: srv, conn: server, writer: bufio.NewWriter(server), tls: true, ehlo: true}
			credentials := base64.StdEncoding.EncodeToString([]byte(tc.authzid + "\x00user@example.com\x00password"))
			done := make(chan struct{})
			go func() { p.authenticate("PLAIN " + credentials); close(done) }()
			_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
			reply, err := bufio.NewReader(client).ReadString('\n')
			if err != nil || !strings.HasPrefix(reply, tc.want) {
				t.Fatalf("AUTH PLAIN reply=%q err=%v", reply, err)
			}
			<-done
			if (p.account != nil) != (tc.want == "235 ") {
				t.Fatalf("authenticated account=%v for response %q", p.account, reply)
			}
		})
	}
}
