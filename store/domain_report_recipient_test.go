package store

import "testing"

func TestDomainReportRecipientMustBeActiveAndLocal(t *testing.T) {
	root := t.TempDir()
	db, err := Open(root+"/mail.db", root+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	one, err := db.CreateDomain(&Domain{Domain: "one.example", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	two, err := db.CreateDomain(&Domain{Domain: "two.example", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	local, err := db.CreateAccount(&Account{DomainID: one, Email: "reports@one.example", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	other, err := db.CreateAccount(&Account{DomainID: two, Email: "reports@two.example", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetDomainReportRecipient(one, other); err == nil {
		t.Fatal("cross-domain recipient accepted")
	}
	if err := db.SetDomainReportRecipient(one, local); err != nil {
		t.Fatal(err)
	}
	id, email, err := db.DomainReportRecipient(one)
	if err != nil || id != local || email != "reports@one.example" {
		t.Fatalf("selected recipient: %d %q %v", id, email, err)
	}
	if _, err := db.Exec(`UPDATE accounts SET is_active=0 WHERE id=?`, local); err != nil {
		t.Fatal(err)
	}
	if err := db.SetDomainReportRecipient(one, local); err == nil {
		t.Fatal("inactive mailbox accepted")
	}
	if err := db.SetDomainReportRecipient(one, 0); err != nil {
		t.Fatal(err)
	}
	id, email, err = db.DomainReportRecipient(one)
	if err != nil || id != 0 || email != "" {
		t.Fatalf("clear selection: %d %q %v", id, email, err)
	}
}
