package store

import (
	"strings"
	"testing"
)

func TestSMTPAuthPolicyAndAppCredentialLifecycle(t *testing.T) {
	root := t.TempDir()
	db, err := Open(root+"/mail.db", root+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&Account{DomainID: domainID, Email: "alice@example.test", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	password, app, err := db.SMTPAllowedCredentials(accountID)
	if err != nil || !password || !app {
		t.Fatalf("default policy: %v %v %v", password, app, err)
	}
	secret, err := db.CreateSMTPAppPassword(accountID, "Thunderbird")
	if err != nil || !strings.HasPrefix(secret, "gm_") {
		t.Fatalf("create: %q %v", secret, err)
	}
	var stored string
	if err := db.QueryRow(`SELECT secret_hash FROM smtp_app_passwords WHERE account_id=?`, accountID).Scan(&stored); err != nil || stored == secret || strings.Contains(stored, secret) {
		t.Fatalf("secret exposed in storage: %q %v", stored, err)
	}
	id, err := db.VerifySMTPAppPassword(accountID, secret)
	if err != nil || id == 0 {
		t.Fatalf("verify: %d %v", id, err)
	}
	if err := db.SetSMTPUserAuthMode(accountID, SMTPAuthApp); err != nil {
		t.Fatal(err)
	}
	password, app, err = db.SMTPAllowedCredentials(accountID)
	if err != nil || password || !app {
		t.Fatalf("user app-only: %v %v %v", password, app, err)
	}
	if err := db.SetSMTPAdminAuthMode(SMTPAuthPassword); err != nil {
		t.Fatal(err)
	}
	password, app, err = db.SMTPAllowedCredentials(accountID)
	if err != nil || password || app {
		t.Fatalf("admin ceiling: %v %v %v", password, app, err)
	}
	if err := db.SetSMTPUserAuthMode(accountID, SMTPAuthApp); err == nil {
		t.Fatal("accepted user setting forbidden by admin")
	}
	if _, err := db.CreateSMTPAppPassword(accountID, "blocked"); err == nil {
		t.Fatal("created app credential while disabled")
	}
	if err := db.SetSMTPAdminAuthMode(SMTPAuthBoth); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeSMTPAppPassword(accountID, id); err != nil {
		t.Fatal(err)
	}
	if active, err := db.SMTPAppPasswordExists(accountID, id); err != nil || active {
		t.Fatalf("revoked credential remained active: %v %v", active, err)
	}
	if got, err := db.VerifySMTPAppPassword(accountID, secret); err != nil || got != 0 {
		t.Fatalf("revoked credential still works: %d %v", got, err)
	}
	if err := db.SetSMTPUserAuthMode(accountID, SMTPAuthDisabled); err != nil {
		t.Fatal(err)
	}
	password, app, err = db.SMTPAllowedCredentials(accountID)
	if err != nil || password || app {
		t.Fatalf("disabled policy: %v %v %v", password, app, err)
	}
}
