package reporting

import (
	"strings"
	"testing"
	"time"

	"gomail/store"
)

func TestGenerateTLSReportGroupsPoliciesAndSessions(t *testing.T) {
	db, err := store.Open(t.TempDir()+"/mail.db", t.TempDir()+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	sts := store.TLSEvent{RecipientDomain: "example.net", PolicyType: "sts",
		PolicyDomain: "example.net", PolicyString: []string{"version: STSv1", "mode: enforce"},
		MXHostPattern: []string{"*.example.net"}, SendingMTAIP: "192.0.2.1",
		ReceivingMXHostname: "mx.example.net", ReceivingIP: "192.0.2.2"}
	sts.Successful = true
	if err := db.RecordTLSEvent(sts); err != nil {
		t.Fatal(err)
	}
	sts.Successful = false
	sts.FailureReason = "certificate-expired"
	sts.FailureReasonCode = "x509: certificate has expired"
	if err := db.RecordTLSEvent(sts); err != nil || db.RecordTLSEvent(sts) != nil {
		t.Fatalf("recording failures: %v", err)
	}
	if err := db.RecordTLSEvent(store.TLSEvent{RecipientDomain: "example.net", Successful: true,
		PolicyType: "no-policy-found", PolicyDomain: "example.net"}); err != nil {
		t.Fatal(err)
	}

	report, err := GenerateTLSReport(db, "sender.example", "example.net", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Policies) != 2 {
		t.Fatalf("got %d policy groups, want 2", len(report.Policies))
	}
	var found bool
	for _, policy := range report.Policies {
		if policy.Policy.PolicyType != "sts" {
			continue
		}
		found = true
		if policy.Summary.TotalSuccessfulSessionCount != 1 || policy.Summary.TotalFailureSessionCount != 2 {
			t.Fatalf("unexpected STS summary: %+v", policy.Summary)
		}
		if len(policy.FailureDetails) != 1 || policy.FailureDetails[0].FailedSessionCount != 2 {
			t.Fatalf("failures not aggregated: %+v", policy.FailureDetails)
		}
	}
	if !found {
		t.Fatal("STS policy group missing")
	}

	message := BuildTLSRPTEmail("sender.example", "postmaster@sender.example", report, "reports@example.net")
	for _, want := range []string{"TLS-Report-Domain: example.net", "TLS-Report-Submitter: sender.example",
		"multipart/report; report-type=\"tlsrpt\"", "application/tlsrpt+gzip", ".json.gz\""} {
		if !strings.Contains(message, want) {
			t.Errorf("message missing %q", want)
		}
	}
}
