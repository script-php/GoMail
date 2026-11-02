package store

import (
	"fmt"
	"sync"
	"testing"
)

func TestLocalAliasDeliveryDoesNotCreateLogin(t *testing.T) {
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
	accountID, err := db.CreateAccount(&Account{DomainID: domainID, Email: "admin@example.test", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAlias("postmaster@example.test", accountID); err != nil {
		t.Fatal(err)
	}
	if acct, err := db.GetAccountByEmail("postmaster@example.test"); err != nil || acct != nil {
		t.Fatalf("alias became login: %+v %v", acct, err)
	}
	acct, err := db.GetDeliveryAccount("postmaster@example.test")
	if err != nil || acct == nil || acct.ID != accountID {
		t.Fatalf("alias delivery: %+v %v", acct, err)
	}
	if err := db.CreateAlias("admin@example.test", accountID); err == nil {
		t.Fatal("alias shadowed real account")
	}
	if err := db.CreateAlias("postmaster@external.test", accountID); err == nil {
		t.Fatal("accepted external alias domain")
	}
	if _, err := db.CreateAccount(&Account{DomainID: domainID, Email: "postmaster@example.test", PasswordHash: "unused", IsActive: true}); err == nil {
		t.Fatal("created account shadowing alias")
	}
	if err := db.DeleteAlias("postmaster@example.test"); err != nil {
		t.Fatal(err)
	}
	if acct, err := db.GetDeliveryAccount("postmaster@example.test"); err != nil || acct != nil {
		t.Fatalf("deleted alias still resolves: %+v %v", acct, err)
	}
}

func TestUserAliasPermissionRevocationRemovesOnlySelfServiceAliases(t *testing.T) {
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
	accountID, err := db.CreateAccount(&Account{DomainID: domainID, Email: "alice@example.test", PasswordHash: "unused", IsActive: true, AllowAliases: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateUserAlias("shopping@example.test", accountID); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateUserAlias("postmaster@example.test", accountID); err == nil {
		t.Fatal("user created reserved alias")
	}
	if err := db.CreateUserAlias("other@external.test", accountID); err == nil {
		t.Fatal("user created alias on another domain")
	}
	if err := db.CreateAlias("postmaster@example.test", accountID); err != nil {
		t.Fatal(err)
	}
	account, err := db.GetAccount(accountID)
	if err != nil {
		t.Fatal(err)
	}
	account.AllowAliases = false
	if err := db.UpdateAccount(account); err != nil {
		t.Fatal(err)
	}
	if got, err := db.ListUserAliases(accountID); err != nil || len(got) != 0 {
		t.Fatalf("revoked aliases: %+v %v", got, err)
	}
	if got, err := db.GetDeliveryAccount("shopping@example.test"); err != nil || got != nil {
		t.Fatalf("revoked alias still delivers: %+v %v", got, err)
	}
	if got, err := db.GetDeliveryAccount("postmaster@example.test"); err != nil || got == nil {
		t.Fatalf("admin alias removed: %+v %v", got, err)
	}
	if err := db.CreateUserAlias("new@example.test", accountID); err == nil {
		t.Fatal("revoked user created alias")
	}
}

func TestPostmasterFallsBackToActiveAdministrator(t *testing.T) {
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
	adminID, err := db.CreateAccount(&Account{DomainID: domainID, Email: "admin@example.test", PasswordHash: "unused", IsActive: true, IsAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"postmaster@example.test", "PoStMaStEr@example.test"} {
		acct, err := db.GetDeliveryAccount(addr)
		if err != nil || acct == nil || acct.ID != adminID {
			t.Fatalf("%s: %+v %v", addr, acct, err)
		}
	}
}

func TestUserAliasLimitUnderConcurrentCreation(t *testing.T) {
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
	accountID, err := db.CreateAccount(&Account{DomainID: domainID, Email: "alice@example.test", PasswordHash: "unused", IsActive: true, AllowAliases: true})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 35; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = db.CreateUserAlias(fmt.Sprintf("alias%d@example.test", i), accountID)
		}(i)
	}
	wg.Wait()
	aliases, err := db.ListUserAliases(accountID)
	if err != nil || len(aliases) != 20 {
		t.Fatalf("aliases=%d err=%v", len(aliases), err)
	}
}
