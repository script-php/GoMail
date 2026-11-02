package reporting

import (
	"bytes"
	"fmt"
	"mime/quotedprintable"
	"strings"
	"testing"
	"time"

	"gomail/store"
)

func TestReceivedReportScannerIsOptInAndIdempotent(t *testing.T) {
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
	start := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	tlsReport := &TLSReport{OrganizationName: "google.com", ContactInfo: "noreply@google.com", ReportID: "sample@google.com",
		DateRange: TLSDateRange{StartDatetime: start.Format(time.RFC3339), EndDatetime: start.Add(24 * time.Hour).Format(time.RFC3339)},
		Policies:  []TLSPolicy{{Policy: TLSPolicyDesc{PolicyType: "sts", PolicyDomain: "example.test"}, Summary: TLSPolicySummary{TotalSuccessfulSessionCount: 7, TotalFailureSessionCount: 2}}},
	}
	tlsRaw := BuildTLSRPTEmail("google.com", "noreply@google.com", tlsReport, "reports@example.test")
	save := func(id, raw string) {
		t.Helper()
		if _, err := db.SaveMessage(&store.Message{AccountID: accountID, MessageID: id, Direction: "inbound", RawMessage: []byte(raw), ReceivedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	save("tls", tlsRaw)
	if imported, err := ScanReceivedReports(db); err != nil || imported != 0 {
		t.Fatalf("disabled scanner imported=%d err=%v", imported, err)
	}
	if err := db.SaveReportInboxSettings(true, accountID); err != nil {
		t.Fatal(err)
	}
	if imported, err := ScanReceivedReports(db); err != nil || imported != 1 {
		t.Fatalf("TLS scan imported=%d err=%v", imported, err)
	}
	dmarc := `<?xml version="1.0"?><feedback><report_metadata><org_name>sender.example</org_name><report_id>dm-1</report_id><date_range><begin>1792195200</begin><end>1792281600</end></date_range></report_metadata><policy_published><domain>example.test</domain></policy_published><record><row><source_ip>192.0.2.1</source_ip><count>3</count><policy_evaluated><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row></record></feedback>`
	dmarcRaw := fmt.Sprintf("From: sender@example.net\r\nTo: reports@example.test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=report\r\n\r\n--report\r\nContent-Type: text/plain\r\n\r\nreport\r\n--report\r\nContent-Type: application/xml\r\nContent-Disposition: attachment; filename=report.xml\r\n\r\n%s\r\n--report--\r\n", dmarc)
	save("dmarc", dmarcRaw)
	if imported, err := ScanReceivedReports(db); err != nil || imported != 1 {
		t.Fatalf("DMARC scan imported=%d err=%v", imported, err)
	}
	if imported, err := ScanReceivedReports(db); err != nil || imported != 0 {
		t.Fatalf("duplicate scan imported=%d err=%v", imported, err)
	}
	save("provider-retry", tlsRaw)
	if imported, err := ScanReceivedReports(db); err != nil || imported != 0 {
		t.Fatalf("duplicate provider report imported=%d err=%v", imported, err)
	}
	reports, err := db.ListReceivedReports(10, 0)
	if err != nil || len(reports) != 2 {
		t.Fatalf("history=%v err=%v", reports, err)
	}
	if reports[0].Kind != "dmarc" || reports[0].Failures != 3 || reports[1].Kind != "tls-rpt" || reports[1].Successes != 7 || reports[1].Failures != 2 {
		t.Fatalf("unexpected summaries: %+v", reports)
	}
	totals, err := db.ReceivedReportSummary()
	if err != nil || totals.DMARCCount != 1 || totals.TLSCount != 1 || totals.Successes != 7 || totals.Failures != 5 {
		t.Fatalf("dashboard totals=%+v err=%v", totals, err)
	}
	if err := db.SaveReportInboxSettings(false, accountID); err != nil {
		t.Fatal(err)
	}
	save("later", tlsRaw)
	if imported, err := ScanReceivedReports(db); err != nil || imported != 0 {
		t.Fatalf("disabled scanner imported=%d err=%v", imported, err)
	}
}

func TestReportScannerKeepsValidPartAndRetriesMalformedMessage(t *testing.T) {
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
	if err := db.SaveReportInboxSettings(true, accountID); err != nil {
		t.Fatal(err)
	}
	xml := `<feedback><report_metadata><org_name>sender.test</org_name><report_id>good-1</report_id><date_range><begin>1792195200</begin><end>1792281600</end></date_range></report_metadata><policy_published><domain>example.test</domain></policy_published></feedback>`
	var encoded bytes.Buffer
	w := quotedprintable.NewWriter(&encoded)
	if _, err := w.Write([]byte(xml)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw := "From: sender@sender.test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=reports\r\n\r\n" +
		"--reports\r\nContent-Type: application/xml\r\nContent-Disposition: attachment; filename=bad.xml\r\n\r\n<broken>\r\n" +
		"--reports\r\nContent-Type: application/xml\r\nContent-Transfer-Encoding: quoted-printable\r\nContent-Disposition: attachment; filename=good.xml\r\n\r\n" + encoded.String() + "\r\n--reports--\r\n"
	if _, err := db.SaveMessage(&store.Message{AccountID: accountID, MessageID: "mixed", Direction: "inbound", RawMessage: []byte(raw), ReceivedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if imported, err := ScanReceivedReports(db); err != nil || imported != 1 {
		t.Fatalf("imported=%d err=%v", imported, err)
	}
	var failures int
	if err := db.QueryRow(`SELECT COUNT(*) FROM report_inbox_failures WHERE account_id=?`, accountID).Scan(&failures); err != nil || failures != 1 {
		t.Fatalf("failures=%d err=%v", failures, err)
	}
	if err := db.ResetReportInboxFailureRetries(accountID); err != nil {
		t.Fatal(err)
	}
	if imported, err := ScanReceivedReports(db); err != nil || imported != 0 {
		t.Fatalf("retry imported=%d err=%v", imported, err)
	}
}

func TestReceivedReportRejectsOversizedDecompression(t *testing.T) {
	var body strings.Builder
	body.Grow(maxReportDecoded + 1)
	body.WriteString(strings.Repeat("x", maxReportDecoded+1))
	if _, err := readBoundedReport(strings.NewReader(body.String())); err == nil {
		t.Fatal("accepted oversized decoded report")
	}
}

func TestReceivedReportsOnlyIncludeHostedDomains(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(root+"/mail.db", root+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&store.Domain{Domain: "hosted.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "reports@hosted.test", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveReportInboxSettings(true, accountID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateDomain(&store.Domain{Domain: "second.test", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	base := TLSReport{OrganizationName: "sender.test", ReportID: "mixed", DateRange: TLSDateRange{StartDatetime: start.Format(time.RFC3339), EndDatetime: start.Add(24 * time.Hour).Format(time.RFC3339)}}
	base.Policies = []TLSPolicy{
		{Policy: TLSPolicyDesc{PolicyType: "sts", PolicyDomain: "external.test"}, Summary: TLSPolicySummary{TotalSuccessfulSessionCount: 50}},
		{Policy: TLSPolicyDesc{PolicyType: "sts", PolicyDomain: "HOSTED.TEST."}, Summary: TLSPolicySummary{TotalSuccessfulSessionCount: 2, TotalFailureSessionCount: 1}},
		{Policy: TLSPolicyDesc{PolicyType: "sts", PolicyDomain: "second.test"}, Summary: TLSPolicySummary{TotalSuccessfulSessionCount: 4, TotalFailureSessionCount: 3}},
	}
	raw := BuildTLSRPTEmail("sender.test", "sender@sender.test", &base, "reports@hosted.test")
	if _, err := db.SaveMessage(&store.Message{AccountID: accountID, MessageID: "mixed", Direction: "inbound", RawMessage: []byte(raw), ReceivedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	base.ReportID = "external-only"
	base.Policies = base.Policies[:1]
	raw = BuildTLSRPTEmail("sender.test", "sender@sender.test", &base, "reports@hosted.test")
	if _, err := db.SaveMessage(&store.Message{AccountID: accountID, MessageID: "external-only", Direction: "inbound", RawMessage: []byte(raw), ReceivedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	foreignDMARC := `<?xml version="1.0"?><feedback><report_metadata><org_name>sender.test</org_name><report_id>foreign-dmarc</report_id><date_range><begin>1792195200</begin><end>1792281600</end></date_range></report_metadata><policy_published><domain>external.test</domain></policy_published></feedback>`
	raw = fmt.Sprintf("From: sender@sender.test\r\nTo: reports@hosted.test\r\nMIME-Version: 1.0\r\nContent-Type: application/xml\r\n\r\n%s", foreignDMARC)
	if _, err := db.SaveMessage(&store.Message{AccountID: accountID, MessageID: "foreign-dmarc", Direction: "inbound", RawMessage: []byte(raw), ReceivedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if imported, err := ScanReceivedReports(db); err != nil || imported != 2 {
		t.Fatalf("imported=%d err=%v", imported, err)
	}
	reports, err := db.ListReceivedReports(10, 0)
	if err != nil || len(reports) != 2 {
		t.Fatalf("unexpected hosted reports: %+v, err=%v", reports, err)
	}
	byDomain := map[string]store.ReceivedReport{}
	for _, report := range reports {
		byDomain[report.ReportDomain] = report
		if strings.Contains(report.PayloadJSON, "external.test") {
			t.Fatalf("foreign policy leaked: %+v", report)
		}
	}
	if byDomain["hosted.test"].Successes != 2 || byDomain["hosted.test"].Failures != 1 || byDomain["second.test"].Successes != 4 || byDomain["second.test"].Failures != 3 {
		t.Fatalf("unexpected hosted reports: %+v, err=%v", reports, err)
	}
}
