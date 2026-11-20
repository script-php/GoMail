package store

import (
	"path/filepath"
	"testing"
)

func TestHostedDomainLookupIgnoresASCIICase(t *testing.T) {
	root := t.TempDir()
	db, err := Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domain := &Domain{Domain: "Example.Test", IsActive: true}
	id, err := db.CreateDomain(domain)
	if err != nil {
		t.Fatal(err)
	}
	if domain.Domain != "example.test" {
		t.Fatalf("stored domain=%q", domain.Domain)
	}
	for _, name := range []string{"example.test", "Example.Test", "EXAMPLE.TEST"} {
		got, err := db.GetDomainByName(name)
		if err != nil || got == nil || got.ID != id {
			t.Fatalf("lookup %q: domain=%v err=%v", name, got, err)
		}
	}
	if _, err := db.CreateDomain(&Domain{Domain: "EXAMPLE.TEST", IsActive: true}); err == nil {
		t.Fatal("created duplicate hosted domain differing only by case")
	}
}

func TestAmbiguousLegacyDomainCaseFailsClosed(t *testing.T) {
	root := t.TempDir()
	db, err := Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, name := range []string{"Example.Test", "example.test"} {
		if _, err := db.Exec(`INSERT INTO domains(domain,is_active) VALUES(?,1)`, name); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := db.GetDomainByName("EXAMPLE.TEST"); err == nil || got != nil {
		t.Fatalf("ambiguous lookup selected domain=%v err=%v", got, err)
	}
}
