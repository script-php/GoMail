package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateMailDomain(t *testing.T) {
	for _, domain := range []string{"localhost", "example.com", "xn--bcher-kva.example", "a-b.example"} {
		if err := ValidateMailDomain(domain); err != nil {
			t.Fatalf("valid domain %q: %v", domain, err)
		}
	}
	for _, domain := range []string{"", "bad_domain.test", "-bad.test", "bad-.test", "a..test", "example.test.", "bad name.test", "bücher.example", strings.Repeat("a", 64) + ".test", strings.Repeat("a", 250) + ".test"} {
		if err := ValidateMailDomain(domain); err == nil {
			t.Fatalf("accepted invalid domain %q", domain)
		}
	}
}

func TestDomainStorageRejectsInvalidNameAndRename(t *testing.T) {
	root := t.TempDir()
	db, err := Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.CreateDomain(&Domain{Domain: "bad_domain.test", IsActive: true}); err == nil {
		t.Fatal("invalid domain was stored")
	}
	id, err := db.CreateDomain(&Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := db.GetDomain(id)
	if err != nil {
		t.Fatal(err)
	}
	domain.Domain = "renamed.test"
	if err := db.UpdateDomain(domain); err == nil {
		t.Fatal("domain rename was accepted")
	}
	stored, err := db.GetDomain(id)
	if err != nil || stored.Domain != "example.test" {
		t.Fatalf("stored domain after rejected rename: %+v, %v", stored, err)
	}
	stored.RequireTLS = true
	if err := db.UpdateDomain(stored); err != nil {
		t.Fatalf("ordinary domain settings update failed: %v", err)
	}
}
