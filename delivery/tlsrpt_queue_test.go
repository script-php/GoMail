package delivery

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gomail/auth"
	"gomail/config"
	"gomail/reporting"
	"gomail/store"
)

func TestSystemTLSReportQueuesWithCompressedAttachment(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	private, public, _, err := auth.GenerateDKIMKeyPair("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.CreateDomain(&store.Domain{Domain: "sender.example", IsActive: true, DKIMSelector: "mail", DKIMAlgorithm: "ed25519", DKIMPrivateKey: private, DKIMPublicKey: public})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	report := &reporting.TLSReport{
		OrganizationName: "sender.example", ContactInfo: "postmaster@sender.example",
		DateRange: reporting.TLSDateRange{StartDatetime: start.Format(time.RFC3339), EndDatetime: start.Add(24 * time.Hour).Format(time.RFC3339)},
		ReportID:  "2026.10.17T00.00.00Z+receiver.example@sender.example",
		Policies:  []reporting.TLSPolicy{{Policy: reporting.TLSPolicyDesc{PolicyType: "no-policy-found", PolicyDomain: "receiver.example"}}},
	}
	visibleFrom := "noreply-smtp-tls-reporting@sender.example"
	raw := reporting.BuildTLSRPTEmail("sender.example", visibleFrom, report, "reports@receiver.example")
	q := NewQueue(db, &config.Config{Server: config.ServerConfig{Hostname: "mail.sender.example", Domain: "sender.example"}})
	if err := q.Enqueue("postmaster@sender.example", []string{"reports@receiver.example"}, []byte(raw), 0); err != nil {
		t.Fatalf("system TLS-RPT attachment could not be queued: %v", err)
	}
	var queued []byte
	if err := db.QueryRow(`SELECT raw_message FROM outbound_queue WHERE rcpt_to = ?`, "reports@receiver.example").Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(queued), "application/tlsrpt+gzip") || !strings.Contains(string(queued), "DKIM-Signature:") {
		t.Fatal("queued report lost attachment or DKIM signature")
	}
}
