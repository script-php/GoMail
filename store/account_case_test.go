package store

import (
	"path/filepath"
	"testing"
)

func TestAccountAddressesAreCaseInsensitive(t *testing.T) {
	root := t.TempDir()
	db, err := Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	input := &Account{DomainID: domainID, Email: "Bob@Example.Test", PasswordHash: "hash", IsActive: true}
	id, err := db.CreateAccount(input)
	if err != nil {
		t.Fatal(err)
	}
	if input.Email != "bob@example.test" {
		t.Fatalf("created email=%q", input.Email)
	}
	for _, address := range []string{"bob@example.test", "Bob@example.test", "BOB@EXAMPLE.TEST"} {
		account, err := db.GetDeliveryAccount(address)
		if err != nil || account == nil || account.ID != id {
			t.Fatalf("delivery lookup for %q: account=%v err=%v", address, account, err)
		}
	}
	if _, err := db.CreateAccount(&Account{DomainID: domainID, Email: "BOB@example.test", PasswordHash: "hash", IsActive: true}); err == nil {
		t.Fatal("created account differing only by case")
	}
	otherID, err := db.CreateAccount(&Account{DomainID: domainID, Email: "other@example.test", PasswordHash: "hash", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	other, err := db.GetAccount(otherID)
	if err != nil {
		t.Fatal(err)
	}
	other.Email = "BOB@example.test"
	if err := db.UpdateAccount(other); err == nil {
		t.Fatal("renamed account to address differing only by case")
	}
}

func TestAmbiguousLegacyAccountCaseFailsClosed(t *testing.T) {
	root := t.TempDir()
	db, err := Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"Bob@example.test", "bob@example.test"} {
		if _, err := db.Exec(`INSERT INTO accounts(domain_id,email,password_hash,is_active) VALUES(?,?,?,1)`, domainID, address, "hash"); err != nil {
			t.Fatal(err)
		}
	}
	if account, err := db.GetAccountByEmail("BOB@example.test"); err == nil || account != nil {
		t.Fatalf("ambiguous lookup selected account=%v err=%v", account, err)
	}
}

func TestAccountCannotClaimAddressOutsideHostedDomain(t *testing.T) {
	root := t.TempDir()
	db, err := Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateAccount(&Account{DomainID: domainID, Email: "alice@other.test", PasswordHash: "hash", IsActive: true}); err == nil {
		t.Fatal("created an account for an unhosted address")
	}
	id, err := db.CreateAccount(&Account{DomainID: domainID, Email: "alice@example.test", PasswordHash: "hash", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	account, err := db.GetAccount(id)
	if err != nil || account == nil {
		t.Fatalf("load account: %v", err)
	}
	account.Email = "alice@other.test"
	if err := db.UpdateAccount(account); err == nil {
		t.Fatal("moved account to an unhosted address")
	}
	current, err := db.GetAccount(id)
	if err != nil || current.Email != "alice@example.test" {
		t.Fatalf("failed edit changed stored address: %+v, %v", current, err)
	}
}
