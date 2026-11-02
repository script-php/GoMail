package mailclient

import (
	"bufio"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gomail/config"
	"gomail/store"
)

func TestSubmissionAppCredentialRespectsPolicyAndRevocation(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(root+"/mail.db", root+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("account-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "user@example.test", PasswordHash: string(hash), IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := db.CreateSMTPAppPassword(accountID, "site")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(&config.Config{Clients: config.MailClientsConfig{AuthAttempts: 100, ReadTimeout: 2, WriteTimeout: 2}}, db, nil, nil)
	check := func(password, want string) *submissionSession {
		t.Helper()
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()
		p := &submissionSession{server: srv, conn: server, writer: bufio.NewWriter(server), tls: true, ehlo: true}
		encoded := base64.StdEncoding.EncodeToString([]byte("\x00user@example.test\x00" + password))
		done := make(chan struct{})
		go func() { p.authenticate("PLAIN " + encoded); close(done) }()
		_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
		reply, err := bufio.NewReader(client).ReadString('\n')
		if err != nil || !strings.HasPrefix(reply, want) {
			t.Fatalf("password=%q reply=%q err=%v", password, reply, err)
		}
		<-done
		return p
	}
	if p := check(secret, "235 "); p.authMethod != "app" || p.appSecretID == 0 {
		t.Fatal("app credential not identified")
	}
	if err := db.SetSMTPUserAuthMode(accountID, store.SMTPAuthApp); err != nil {
		t.Fatal(err)
	}
	check("account-password", "535 ")
	check(secret, "235 ")
	if err := db.SetSMTPAdminAuthMode(store.SMTPAuthPassword); err != nil {
		t.Fatal(err)
	}
	check(secret, "535 ")
	if err := db.SetSMTPAdminAuthMode(store.SMTPAuthBoth); err != nil {
		t.Fatal(err)
	}
	credentials, err := db.ListSMTPAppPasswords(accountID)
	if err != nil || len(credentials) != 1 {
		t.Fatalf("credentials=%v err=%v", credentials, err)
	}
	if err := db.RevokeSMTPAppPassword(accountID, credentials[0].ID); err != nil {
		t.Fatal(err)
	}
	check(secret, "535 ")
}
