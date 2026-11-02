package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestTLSReportRetryStateRetainsWindow(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "mail.db"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.RecordTLSFailure("example.net", "certificate-expired", "192.0.2.1", "mx.example.net", "192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	end := time.Now().Add(time.Minute)
	start, eligible, err := db.GetTLSReportStart("example.net", end)
	if err != nil || !eligible || start.IsZero() {
		t.Fatalf("initial window: start=%s eligible=%v err=%v", start, eligible, err)
	}
	if err := db.RecordTLSReportFailure("example.net", start.Add(-time.Second), end, errors.New("endpoint unavailable")); err != nil {
		t.Fatal(err)
	}
	var attempts int
	var lastError string
	if err := db.QueryRow(`SELECT report_attempts, report_last_error FROM tls_failures WHERE recipient_domain=?`, "example.net").Scan(&attempts, &lastError); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || lastError != "endpoint unavailable" {
		t.Fatalf("retry state attempts=%d error=%q", attempts, lastError)
	}
	if _, eligible, err := db.GetTLSReportStart("example.net", end); err != nil || eligible {
		t.Fatalf("backoff was not enforced: eligible=%v err=%v", eligible, err)
	}
	if _, err := db.Exec(`UPDATE tls_failures SET next_report_attempt=?`, databaseTime(time.Now().Add(-time.Minute))); err != nil {
		t.Fatal(err)
	}
	retriedStart, eligible, err := db.GetTLSReportStart("example.net", end)
	if err != nil || !eligible || !retriedStart.Equal(start) {
		t.Fatalf("retry window changed: first=%s retry=%s eligible=%v err=%v", start, retriedStart, eligible, err)
	}
}
