package handlers

import (
	"strings"
	"testing"

	"gomail/config"
	"gomail/store"
)

func TestDNSRecordsUseOnlyDeliverableSelectedReportMailbox(t *testing.T) {
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
	accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "reports@example.test", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetDomainReportRecipient(domainID, accountID); err != nil {
		t.Fatal(err)
	}
	domain, err := db.GetDomain(domainID)
	if err != nil {
		t.Fatal(err)
	}
	h := &AdminHandler{db: db, cfg: &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test"}}}
	values := func() string {
		var result string
		for _, record := range h.buildDNSRecords(domain) {
			result += record.Value + "\n"
		}
		return result
	}
	if !strings.Contains(values(), "rua=mailto:reports@example.test") {
		t.Fatal("selected report recipient missing")
	}
	if _, err := db.Exec(`UPDATE accounts SET is_active=0 WHERE id=?`, accountID); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(values(), "rua=mailto:") {
		t.Fatal("inactive report recipient exposed in copyable DNS")
	}
	otherDomain, err := db.CreateDomain(&store.Domain{Domain: "other.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE accounts SET domain_id=?,is_active=1,email='reports@other.test' WHERE id=?`, otherDomain, accountID); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(values(), "rua=mailto:") {
		t.Fatal("moved cross-domain mailbox exposed in DNS")
	}
}
