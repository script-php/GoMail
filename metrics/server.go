package metrics

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"gomail/config"
	"gomail/store"
)

var processStarted = time.Now()

type Server struct {
	db                *store.DB
	token             string
	certificateExpiry *time.Time
	http              *http.Server
}

func NewServer(cfg config.MetricsConfig, db *store.DB, certificateExpiry *time.Time) *Server {
	s := &Server{db: db, token: strings.TrimSpace(cfg.BearerToken), certificateExpiry: certificateExpiry}
	mux := http.NewServeMux()
	mux.Handle("/metrics", s)
	s.http = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return s
}

func (s *Server) ListenAndServe() error { return s.http.ListenAndServe() }

func (s *Server) Shutdown(ctx context.Context) error { return s.http.Shutdown(ctx) }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.token != "" {
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(provided) != len(s.token) || subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="gomail-metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	snapshot, err := s.db.GetOperationalMetrics(time.Now())
	if err != nil {
		http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writeMetric(w, "gomail_process_uptime_seconds", "GoMail process uptime.", time.Since(processStarted).Seconds())
	fmt.Fprintln(w, "# HELP gomail_delivery_queue_entries Current outbound queue entries by bounded status.")
	fmt.Fprintln(w, "# TYPE gomail_delivery_queue_entries gauge")
	for _, status := range []string{"pending", "sending", "uncertain", "sent", "failed", "cancelled"} {
		fmt.Fprintf(w, "gomail_delivery_queue_entries{status=%q} %d\n", status, snapshot.QueueByStatus[status])
	}
	writeMetric(w, "gomail_delivery_queue_oldest_seconds", "Age of the oldest pending or sending queue entry.", snapshot.OldestPendingAge)
	writeMetric(w, "gomail_mailbox_used_bytes", "Total bytes stored in active account mailboxes.", float64(snapshot.MailboxUsedBytes))
	writeMetric(w, "gomail_mailbox_configured_quota_bytes", "Sum of configured non-zero mailbox limits.", float64(snapshot.MailboxQuotaBytes))
	writeMetric(w, "gomail_mailbox_quota_limited_accounts", "Active accounts with a configured mailbox limit.", float64(snapshot.QuotaLimited))
	writeMetric(w, "gomail_mailbox_quota_near_limit_accounts", "Active limited accounts at or above 90 percent usage.", float64(snapshot.QuotaNearLimit))
	if disk, diskErr := s.db.DiskPressureStatus(); diskErr == nil && disk.FreeBytes >= 0 {
		writeMetric(w, "gomail_storage_free_bytes", "Lowest available bytes across configured durable storage filesystems.", float64(disk.FreeBytes))
		writeMetric(w, "gomail_storage_warning_threshold_bytes", "Configured free-space warning threshold.", float64(disk.WarningFree))
		writeMetric(w, "gomail_storage_minimum_threshold_bytes", "Configured free-space write-refusal threshold.", float64(disk.MinimumFree))
		if disk.Warning {
			writeMetric(w, "gomail_storage_pressure", "Whether free storage is below the warning threshold.", 1)
		} else {
			writeMetric(w, "gomail_storage_pressure", "Whether free storage is below the warning threshold.", 0)
		}
	}
	writeMetric(w, "gomail_tls_attempts_24h", "Recorded outbound TLS policy evaluations in the last 24 hours.", float64(snapshot.TLSAttempts24Hours))
	writeMetric(w, "gomail_tls_failures_24h", "Recorded failed outbound TLS policy evaluations in the last 24 hours.", float64(snapshot.TLSFailures24Hours))
	if s.certificateExpiry != nil {
		writeMetric(w, "gomail_certificate_expiry_timestamp_seconds", "Unix timestamp when the active server certificate expires.", float64(s.certificateExpiry.Unix()))
	}
	counterValues := counterSnapshot()
	names := make([]string, 0, len(counterValues))
	for name := range counterValues {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		values := counterValues[name]
		fmt.Fprintf(w, "# HELP gomail_%s Monotonic GoMail event counter with a bounded outcome label.\n", name)
		fmt.Fprintf(w, "# TYPE gomail_%s counter\n", name)
		labels := make([]string, 0, len(allowedLabels[name]))
		for label := range allowedLabels[name] {
			labels = append(labels, label)
		}
		sort.Strings(labels)
		for _, label := range labels {
			fmt.Fprintf(w, "gomail_%s{outcome=%q} %d\n", name, label, values[label])
		}
	}
}

func writeMetric(w http.ResponseWriter, name, help string, value float64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %s\n", name, help, name, name, strconv.FormatFloat(value, 'f', -1, 64))
}
