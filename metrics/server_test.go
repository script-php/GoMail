package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gomail/config"
	"gomail/store"
)

func metricsDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(":memory:", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestMetricsHandler(t *testing.T) {
	db := metricsDB(t)
	db.ConfigureDiskPressure(1<<62, 1, t.TempDir())
	handler := NewServer(config.MetricsConfig{}, db, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	for _, wanted := range []string{
		"gomail_process_uptime_seconds",
		`gomail_delivery_queue_entries{status="pending"}`,
		"gomail_mailbox_used_bytes",
		"gomail_tls_failures_24h",
		"gomail_storage_free_bytes",
		"gomail_storage_pressure",
	} {
		if !strings.Contains(recorder.Body.String(), wanted) {
			t.Errorf("metrics output missing %q", wanted)
		}
	}
}

func TestMetricsBearerAuthentication(t *testing.T) {
	handler := NewServer(config.MetricsConfig{BearerToken: "secret"}, metricsDB(t), nil)
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "Bearer secret")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("authenticated status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestMetricsCountersAndCertificateExpiry(t *testing.T) {
	counters.Lock()
	counters.values = map[string]map[string]uint64{}
	counters.Unlock()
	IncSMTP("accepted")
	IncSMTP("not-allowed")
	IncQuota("draft")
	IncOutboundLimit("submission")
	expiry := time.Unix(2_000_000_000, 0)
	handler := NewServer(config.MetricsConfig{}, metricsDB(t), &expiry)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	output := recorder.Body.String()
	for _, wanted := range []string{
		`gomail_smtp_messages_total{outcome="accepted"} 1`,
		`gomail_quota_rejections_total{outcome="draft"} 1`,
		`gomail_outbound_limit_rejections_total{outcome="submission"} 1`,
		`gomail_certificate_expiry_timestamp_seconds 2000000000`,
	} {
		if !strings.Contains(output, wanted) {
			t.Errorf("metrics output missing %q", wanted)
		}
	}
	if strings.Contains(output, "not-allowed") {
		t.Fatal("unbounded counter label was exported")
	}
}
