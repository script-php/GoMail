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

func TestIMAPSameMailboxMoveSendsCopyUIDBeforeExpunge(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.test')`); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("test-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO accounts(id,domain_id,email,password_hash,is_active) VALUES(1,1,'user@example.test',?,1)`, string(hash)); err != nil {
		t.Fatal(err)
	}
	if err := db.DefaultFolders(1); err != nil {
		t.Fatal(err)
	}
	inbox, err := db.GetFolderByType(1, "inbox")
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.SaveMessage(&store.Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "same-mailbox-move", Direction: "inbound", RawMessage: []byte("Subject: test\r\n\r\nbody\r\n"), ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test"}, SMTP: config.SMTPConfig{MaxMessageSize: 1024}, Clients: config.MailClientsConfig{ReadTimeout: 2, WriteTimeout: 2, MaxConnections: 1, AuthAttempts: 10}}
	srv := NewServer(cfg, db, nil, nil)
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	go srv.handleIMAP(serverConn)
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(clientConn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	command := func(tag, line string) string {
		t.Helper()
		if _, err := fmt.Fprint(clientConn, tag+" "+line+"\r\n"); err != nil {
			t.Fatal(err)
		}
		var response strings.Builder
		for {
			part, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			response.WriteString(part)
			if strings.HasPrefix(part, tag+" ") {
				return response.String()
			}
		}
	}
	if response := command("a1", "LOGIN user@example.test test-password"); !strings.Contains(response, "a1 OK") {
		t.Fatal(response)
	}
	if response := command("a2", "SELECT Inbox"); !strings.Contains(response, "a2 OK") {
		t.Fatal(response)
	}
	response := command("a3", "UID MOVE 1 Inbox")
	copyAt, expungeAt := strings.Index(response, "* OK [COPYUID "), strings.Index(response, "* 1 EXPUNGE")
	if copyAt < 0 || expungeAt < 0 || copyAt >= expungeAt || !strings.Contains(response, "a3 OK MOVE completed") {
		t.Fatalf("same-mailbox MOVE response order: %q", response)
	}
	state, err := db.GetIMAPMessageState(1, id)
	if err != nil || state == nil || state.UID <= 1 || state.FolderID != inbox.ID {
		t.Fatalf("state=%#v err=%v", state, err)
	}
}
