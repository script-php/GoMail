package reporting

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strings"
	"testing"
	"time"

	"gomail/store"
)

func TestParseTLSRPTRecordDestinations(t *testing.T) {
	got, err := ParseTLSRPTRecord("v=TLSRPTv1; rua=mailto:reports@example.com,https://reports.example.net/v1/tlsrpt; unknown=x")
	if err != nil || len(got) != 2 || got[0] != "mailto:reports@example.com" || got[1] != "https://reports.example.net/v1/tlsrpt" {
		t.Fatalf("destinations=%v err=%v", got, err)
	}
	for _, invalid := range []string{"v=TLSRPTv2; rua=mailto:a@example.com", "v=TLSRPTv1; rua=http://insecure.example/report", "v=TLSRPTv1; rua=mailto:not-an-address"} {
		if _, err := ParseTLSRPTRecord(invalid); err == nil {
			t.Errorf("accepted invalid policy %q", invalid)
		}
	}
}

func TestTLSRPTConflictingRecordsAreIgnored(t *testing.T) {
	valid := "v=TLSRPTv1; rua=mailto:reports@example.com"
	if _, err := parseTLSRPTRecords([]string{valid, "v=TLSRPTv1; rua=mailto:other@example.com"}); err == nil {
		t.Fatal("multiple policies were combined")
	}
	got, err := parseTLSRPTRecords([]string{"unrelated=txt", valid})
	if err != nil || len(got) != 1 || got[0] != "mailto:reports@example.com" {
		t.Fatalf("records=%v err=%v", got, err)
	}
	for _, bad := range []string{"rua=mailto:reports@example.com; v=TLSRPTv1", "v=TLSRPTv1; rua=mailto:a@example.com; rua=mailto:b@example.com"} {
		if _, err := ParseTLSRPTRecord(bad); err == nil {
			t.Errorf("accepted malformed policy %q", bad)
		}
	}
}

func TestPostTLSRPTHTTPS(t *testing.T) {
	report := &TLSReport{OrganizationName: "sender.example", ReportID: "report-1"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/tlsrpt+gzip" {
			t.Errorf("unexpected request: %s %s", request.Method, request.Header.Get("Content-Type"))
		}
		reader, err := gzip.NewReader(request.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer reader.Close()
		var received TLSReport
		if err := json.NewDecoder(io.LimitReader(reader, 1<<20)).Decode(&received); err != nil || received.ReportID != report.ReportID {
			t.Errorf("bad report: %+v err=%v", received, err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	if err := PostTLSRPT(context.Background(), server.Client(), server.URL, report); err != nil {
		t.Fatal(err)
	}
}

func TestNextUTCMidnight(t *testing.T) {
	now := time.Date(2026, 9, 24, 23, 59, 59, 0, time.FixedZone("EEST", 3*60*60))
	want := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	if got := nextUTCMidnight(now); !got.Equal(want) {
		t.Fatalf("next midnight=%s want=%s", got, want)
	}
}

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

	message := BuildTLSRPTEmail("sender.example", "noreply-smtp-tls-reporting@sender.example", report, "reports@example.net")
	for _, want := range []string{"TLS-Report-Domain: example.net", "TLS-Report-Submitter: sender.example",
		"multipart/report; report-type=\"tlsrpt\"", "application/tlsrpt+gzip", ".json.gz\""} {
		if !strings.Contains(message, want) {
			t.Errorf("message missing %q", want)
		}
	}
	if !strings.Contains(report.ReportID, "@sender.example") {
		t.Fatalf("report ID is not address-shaped: %q", report.ReportID)
	}
	parsed, err := mail.ReadMessage(strings.NewReader(message))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.Get("From") != "noreply-smtp-tls-reporting@sender.example" ||
		!strings.Contains(parsed.Header.Get("Subject"), "Report-ID: <"+report.ReportID+">") {
		t.Fatalf("unexpected report headers: from=%q subject=%q", parsed.Header.Get("From"), parsed.Header.Get("Subject"))
	}
	_, parameters, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	parts := multipart.NewReader(parsed.Body, parameters["boundary"])
	plain, err := parts.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(plain)
	if string(body) != "This is an aggregate TLS report from sender.example\r\n" {
		t.Fatalf("report body=%q", body)
	}
	attachment, err := parts.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if attachment.Header.Get("Content-Type") != "application/tlsrpt+gzip" ||
		!strings.HasSuffix(attachment.FileName(), "!001.json.gz") {
		t.Fatalf("report attachment: type=%q name=%q", attachment.Header.Get("Content-Type"), attachment.FileName())
	}
	compressed, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, attachment))
	if err != nil {
		t.Fatal(err)
	}
	unzipped, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	defer unzipped.Close()
	var attached TLSReport
	if err := json.NewDecoder(unzipped).Decode(&attached); err != nil || attached.ReportID != report.ReportID {
		t.Fatalf("report payload=%+v err=%v", attached, err)
	}
}
