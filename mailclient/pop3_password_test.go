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

func TestPOP3PASSPreservesLeadingAndTrailingSpaces(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	password := "  space within password  "
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.test'); INSERT INTO accounts(id,domain_id,email,password_hash,is_active) VALUES(1,1,'user@example.test',?,1)`, string(hash)); err != nil {
		t.Fatal(err)
	}
	server := NewServer(&config.Config{Clients: config.MailClientsConfig{ReadTimeout: 5, WriteTimeout: 5, MaxConnections: 1, AuthAttempts: 10}}, db, nil, nil)
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	go server.handlePOP3(serverSide)
	_ = clientSide.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(clientSide)
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK ") {
		t.Fatalf("POP3 greeting=%q err=%v", line, err)
	}
	for _, tc := range []struct{ command, prefix string }{
		{"USER user@example.test", "+OK "},
		{"PASS " + password, "+OK maildrop"},
		{"QUIT", "+OK bye"},
	} {
		if _, err := fmt.Fprintf(clientSide, "%s\r\n", tc.command); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, tc.prefix) {
			t.Fatalf("command %q: response=%q err=%v", tc.command, line, err)
		}
	}
}
