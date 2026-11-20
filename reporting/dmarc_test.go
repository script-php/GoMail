package reporting

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"gomail/config"
	"gomail/store"
)

func TestDMARC9990AggregateReportShape(t *testing.T) {
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	data, err := GenerateDMARCAggregateReport("example.test", "reports@receiver.test", "receiver.test",
		PolicyPublished{Domain: "example.test", P: "none", NP: "reject", Testing: "y", DiscoveryMethod: "treewalk"},
		[]ReportRecord{{Row: Row{SourceIP: "192.0.2.1", Count: 1, PolicyEval: PolicyEvaluated{Disposition: "none", DKIM: "fail", SPF: "fail"}}, Identifiers: Identifiers{HeaderFrom: "example.test"}}}, start, start.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		XMLName xml.Name
		Policy  struct {
			NP      string `xml:"np"`
			Testing string `xml:"testing"`
		} `xml:"policy_published"`
	}
	if err := xml.Unmarshal([]byte(data), &root); err != nil {
		t.Fatal(err)
	}
	if root.XMLName.Space != dmarcReportNamespace || root.Policy.NP != "reject" || root.Policy.Testing != "y" || strings.Contains(data, "<pct>") {
		t.Fatalf("not an RFC 9990 report: %s", data)
	}
}

func TestDMARC9990MissingPDefaultsToNoneForReporting(t *testing.T) {
	previous := lookupReportingTXT
	lookupReportingTXT = func(string) ([]string, error) {
		return []string{"v=DMARC1; rua=mailto:reports@example.test; t=y; np=reject; pct=0"}, nil
	}
	t.Cleanup(func() { lookupReportingTXT = previous })
	policy, err := lookupDMARCForReporting("example.test")
	if err != nil || policy.P != "none" || policy.NP != "reject" || policy.Testing != "y" {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
}

func TestDMARCReportingUsesExactVersionRecognition(t *testing.T) {
	previous := lookupReportingTXT
	lookupReportingTXT = func(string) ([]string, error) {
		return []string{"v=DMARC12; p=none", "v = DMARC1; p=reject; rua=mailto:reports@example.test"}, nil
	}
	t.Cleanup(func() { lookupReportingTXT = previous })
	policy, err := lookupDMARCForReporting("example.test")
	if err != nil || policy.P != "reject" || len(policy.ReportMailto) != 1 {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
}

func TestDMARCFeedbackProducesAuthenticationResults(t *testing.T) {
	db, err := store.Open(t.TempDir()+"/mail.db", t.TempDir()+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < 2; i++ {
		if err := db.SaveDMARCFeedbackDetailed("header.example", "192.0.2.1", "bounce.example",
			"pass", "signing.example", "mail2026", "pass", "bounce.example", "mfrom", "none"); err != nil {
			t.Fatal(err)
		}
	}
	records, err := getDMARCFeedbackRecords(db, "header.example", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	record := records[0]
	if record.Row.Count != 2 || len(record.AuthResults.DKIM) != 1 || len(record.AuthResults.SPF) != 1 {
		t.Fatalf("authentication results missing: %+v", record)
	}
	if record.AuthResults.DKIM[0].Domain != "signing.example" || record.AuthResults.DKIM[0].Selector != "mail2026" || record.AuthResults.SPF[0].Scope != "mfrom" {
		t.Fatalf("authentication identities lost: %+v", record.AuthResults)
	}
	xmlReport, err := GenerateDMARCAggregateReport("header.example", "postmaster@receiver.example", "receiver.example",
		PolicyPublished{Domain: "header.example", P: "reject"}, records, time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<auth_results>", "<domain>signing.example</domain>", "<selector>mail2026</selector>", "<scope>mfrom</scope>"} {
		if !strings.Contains(xmlReport, want) {
			t.Errorf("report missing %q:\n%s", want, xmlReport)
		}
	}
}

func TestDMARCFeedbackOmitsAbsentAuthenticationIdentities(t *testing.T) {
	db, err := store.Open(t.TempDir()+"/mail.db", t.TempDir()+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.SaveDMARCFeedbackDetailed("header.example", "192.0.2.2", "",
		"none", "", "", "none", "", "mfrom", "none"); err != nil {
		t.Fatal(err)
	}
	records, err := getDMARCFeedbackRecords(db, "header.example", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	if len(records[0].AuthResults.DKIM) != 0 || len(records[0].AuthResults.SPF) != 0 {
		t.Fatalf("absent identities reported: %+v", records[0].AuthResults)
	}
	xmlReport, err := GenerateDMARCAggregateReport("header.example", "postmaster@receiver.example", "receiver.example",
		PolicyPublished{Domain: "header.example", P: "none"}, records, time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"<envelope_from>", "<auth_results><dkim>", "<auth_results><spf>"} {
		if strings.Contains(xmlReport, absent) {
			t.Errorf("report invented %q:\n%s", absent, xmlReport)
		}
	}
	if !strings.Contains(xmlReport, "<auth_results></auth_results>") {
		t.Errorf("report omitted required auth_results container:\n%s", xmlReport)
	}
}

func TestInheritedDMARCPolicyGroupsFeedbackAndReportsAlignment(t *testing.T) {
	db, err := store.Open(t.TempDir()+"/mail.db", t.TempDir()+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.SaveDMARCFeedbackEvaluated("news.example.com", "example.com", "192.0.2.2", "bounce.other.test",
		"pass", "other.test", "mail", "pass", "other.test", "mfrom", "quarantine", false, false); err != nil {
		t.Fatal(err)
	}
	domains, err := db.GetDomainsWithFeedback()
	if err != nil || len(domains) != 1 || domains[0].Domain != "example.com" {
		t.Fatalf("feedback not grouped by policy domain: %+v, %v", domains, err)
	}
	records, err := getDMARCFeedbackRecords(db, "example.com", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	r := records[0]
	if r.Identifiers.HeaderFrom != "news.example.com" || r.Row.PolicyEval.DKIM != "fail" || r.Row.PolicyEval.SPF != "fail" || r.AuthResults.DKIM[0].Result != "pass" || r.AuthResults.SPF[0].Result != "pass" {
		t.Fatalf("raw authentication and alignment were conflated: %+v", r)
	}
}

func TestDMARCReportMailUsesCurrentSubjectAndFilename(t *testing.T) {
	start := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	xmlReport, err := GenerateDMARCAggregateReport("example.com", "postmaster@receiver.example", "mail.receiver.example",
		PolicyPublished{Domain: "example.com", P: "reject"}, nil, start, end)
	if err != nil {
		t.Fatal(err)
	}
	var sent string
	cfg := &config.Config{Server: config.ServerConfig{Hostname: "mail.receiver.example"}}
	err = sendDMARCReport(cfg, func(from, to, message string) error { sent = message; return nil }, "example.com", "receiver.example", "reports@example.com", xmlReport)
	if err != nil {
		t.Fatal(err)
	}
	wantFilename := fmt.Sprintf("mail.receiver.example!example.com!%d!%d.xml.gz", start.Unix(), end.Unix())
	for _, want := range []string{
		"Subject: Report Domain: example.com Submitter: mail.receiver.example Report-ID: <",
		"filename=\"" + wantFilename + "\"",
		"name=\"" + wantFilename + "\"",
	} {
		if !strings.Contains(sent, want) {
			t.Fatalf("report mail missing %q", want)
		}
	}
	marker := "Content-Disposition: attachment; filename=\"" + wantFilename + "\"\r\n\r\n"
	parts := strings.SplitN(sent, marker, 2)
	if len(parts) != 2 {
		t.Fatal("attachment body missing")
	}
	payload := strings.SplitN(parts[1], "\r\n--boundary123--", 2)[0]
	for _, line := range strings.Split(payload, "\r\n") {
		if len(line) > 76 {
			t.Fatalf("base64 MIME line exceeds 76 characters: %d", len(line))
		}
	}
	if _, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(payload, "\r\n", "")); err != nil {
		t.Fatalf("attachment is not valid base64: %v", err)
	}
}

func TestDMARCExternalDestinationAuthorization(t *testing.T) {
	originalLookup := lookupReportingTXT
	defer func() { lookupReportingTXT = originalLookup }()
	var queried string
	lookupReportingTXT = func(name string) ([]string, error) {
		queried = name
		if name == "sender.example._report._dmarc.reports.example.net" {
			return []string{"v=DMARC1"}, nil
		}
		return nil, errors.New("not found")
	}
	if !authorizedDMARCReportDestination("sender.example", "aggregate@reports.example.net") {
		t.Fatal("authorized external destination was rejected")
	}
	if queried != "sender.example._report._dmarc.reports.example.net" {
		t.Fatalf("wrong authorization query: %q", queried)
	}
	if authorizedDMARCReportDestination("sender.example", "aggregate@unauthorized.example") {
		t.Fatal("unauthorized external destination was accepted")
	}
	if !authorizedDMARCReportDestination("sender.example", "aggregate@sender.example") {
		t.Fatal("same-domain destination should not require external authorization")
	}
	addresses := parseReportAddresses("mailto:aggregate@reports.example.net!10m,mailto:second@sender.example")
	if len(addresses) != 2 || addresses[0] != "aggregate@reports.example.net" {
		t.Fatalf("DMARC rua size suffix not parsed: %v", addresses)
	}
}

func TestDMARCReportingRejectsMultiplePolicies(t *testing.T) {
	previous := lookupReportingTXT
	defer func() { lookupReportingTXT = previous }()
	lookupReportingTXT = func(string) ([]string, error) {
		return []string{"v=DMARC1; p=none; rua=mailto:a@example.com", "v=DMARC1; p=reject; rua=mailto:b@example.com"}, nil
	}
	if _, err := lookupDMARCForReporting("example.com"); err == nil {
		t.Fatal("selected one of multiple DMARC policies")
	}
}

func TestDMARCExternalDestinationOverrideStaysOnAuthorizingHost(t *testing.T) {
	previous := lookupReportingTXT
	defer func() { lookupReportingTXT = previous }()
	lookupReportingTXT = func(string) ([]string, error) {
		return []string{"v=DMARC1; rua=mailto:override@reports.example.net"}, nil
	}
	got := resolvedDMARCReportDestinations("sender.example", "original@reports.example.net")
	if len(got) != 1 || got[0] != "override@reports.example.net" {
		t.Fatalf("override=%v", got)
	}
	lookupReportingTXT = func(string) ([]string, error) {
		return []string{"v=DMARC1", "v=DMARC1; rua=mailto:override@reports.example.net"}, nil
	}
	got = resolvedDMARCReportDestinations("sender.example", "original@reports.example.net")
	if len(got) != 1 || got[0] != "override@reports.example.net" {
		t.Fatalf("later override ignored: %v", got)
	}
	lookupReportingTXT = func(string) ([]string, error) { return []string{"v=DMARC1; rua=mailto:third@other.example"}, nil }
	if got := resolvedDMARCReportDestinations("sender.example", "original@reports.example.net"); len(got) != 0 {
		t.Fatalf("cross-host override accepted: %v", got)
	}
}

func TestDMARCUnreportedDaysUseUTCBoundaries(t *testing.T) {
	db, err := store.Open(t.TempDir()+"/mail.db", t.TempDir()+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, value := range []string{"2026-10-20 23:59:00", "2026-10-21 00:01:00", "2026-10-21 12:00:00"} {
		if _, err := db.Exec(`INSERT INTO dmarc_feedback(domain,policy_domain,source_ip,received_at) VALUES(?,?,?,?)`, "example.com", "example.com", "192.0.2.1", value); err != nil {
			t.Fatal(err)
		}
	}
	cutoff := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	days, err := unreportedDMARCDays(db, "example.com", cutoff)
	if err != nil || len(days) != 2 || !days[0].Equal(cutoff.Add(-48*time.Hour)) || !days[1].Equal(cutoff.Add(-24*time.Hour)) {
		t.Fatalf("days=%v err=%v", days, err)
	}
}

func TestDMARCCatchupQueuesOneReportPerUTCDay(t *testing.T) {
	db, err := store.Open(t.TempDir()+"/mail.db", t.TempDir()+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, value := range []string{"2026-10-20 12:00:00", "2026-10-21 12:00:00"} {
		if _, err := db.Exec(`INSERT INTO dmarc_feedback(domain,policy_domain,source_ip,received_at) VALUES(?,?,?,?)`, "example.com", "example.com", "192.0.2.1", value); err != nil {
			t.Fatal(err)
		}
	}
	previous := lookupReportingTXT
	defer func() { lookupReportingTXT = previous }()
	lookupReportingTXT = func(string) ([]string, error) {
		return []string{"v=DMARC1; p=none; rua=mailto:reports@example.com"}, nil
	}
	var sent []string
	queue := func(from, to, message string) error { sent = append(sent, message); return nil }
	cfg := &config.Config{Server: config.ServerConfig{Hostname: "mail.sender.example", Domain: "sender.example"}}
	cutoff := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	if !sendDMARCReportForDomain(cfg, db, queue, &store.Domain{Domain: "example.com"}, cutoff) {
		t.Fatal("catchup sent no reports")
	}
	if len(sent) != 2 {
		t.Fatalf("sent %d daily reports, want 2", len(sent))
	}
	for _, day := range []time.Time{cutoff.Add(-48 * time.Hour), cutoff.Add(-24 * time.Hour)} {
		stamp := fmt.Sprintf("%d!%d", day.Unix(), day.Add(24*time.Hour).Unix())
		found := false
		for _, message := range sent {
			if strings.Contains(message, stamp) {
				found = true
			}
		}
		if !found {
			t.Errorf("report window %s missing", stamp)
		}
	}
	days, err := unreportedDMARCDays(db, "example.com", cutoff)
	if err != nil || len(days) != 0 {
		t.Fatalf("days still pending: %v, %v", days, err)
	}
}
