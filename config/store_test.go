package config

import (
	"strings"
	"testing"
)

func TestStoreConfiguration(t *testing.T) {
	cfg := StoreConfig{}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Database != "sqlite" || cfg.DBPath != "data/mail.db" {
		t.Fatalf("defaults changed: %+v", cfg)
	}
	for _, tc := range []StoreConfig{
		{Database: "postgres"},
		{Database: "mysql"},
		{Database: "mysql", MySQL: MySQLConfig{User: "mail", Name: "mail", Port: -1}},
		{Database: "mysql", MySQL: MySQLConfig{User: "mail", Name: "mail", TLS: "skip-verify"}},
		{Database: "mysql", MySQL: MySQLConfig{User: "mail", Name: "../mail"}},
	} {
		if err := tc.Validate(); err == nil {
			t.Errorf("accepted invalid configuration: %+v", tc)
		}
	}
	cfg = StoreConfig{Database: "MySQL", MySQL: MySQLConfig{User: "mail", Name: "gomail"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.MySQL.Port != 3306 || cfg.MySQL.Host != "127.0.0.1" || cfg.Database != "mysql" {
		t.Fatal("missing MySQL defaults")
	}
}

func TestMetricsConfiguration(t *testing.T) {
	cfg := &Config{Server: ServerConfig{Hostname: "mail.example.com"}, TLS: TLSConfig{Mode: "none"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Metrics.ListenAddr != "127.0.0.1:9090" {
		t.Fatalf("unexpected metrics default: %q", cfg.Metrics.ListenAddr)
	}

	cfg.Metrics = MetricsConfig{Enabled: true, ListenAddr: "0.0.0.0:9090"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "bearer_token") {
		t.Fatalf("expected public metrics authentication error, got %v", err)
	}
	cfg.Metrics.BearerToken = "secret"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("authenticated public metrics listener rejected: %v", err)
	}
}

func TestLoggingFormatValidation(t *testing.T) {
	cfg := &Config{Server: ServerConfig{Hostname: "mail.example.com"}, TLS: TLSConfig{Mode: "none"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Logging.Format != "text" {
		t.Fatalf("default logging format=%q", cfg.Logging.Format)
	}
	cfg.Logging.Format = "xml"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "logging.format") {
		t.Fatalf("expected invalid logging format error, got %v", err)
	}
}

func TestStoragePressureConfiguration(t *testing.T) {
	cfg := &Config{Server: ServerConfig{Hostname: "mail.example.com"}, TLS: TLSConfig{Mode: "none"}, StoragePressure: StoragePressureConfig{WarningFreeBytes: 100, MinimumFreeBytes: 200}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "warning_free_bytes") {
		t.Fatalf("accepted inverted storage thresholds: %v", err)
	}
	cfg.StoragePressure = StoragePressureConfig{WarningFreeBytes: 200, MinimumFreeBytes: 100}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid storage thresholds rejected: %v", err)
	}
	cfg.StoragePressure.MinimumFreeBytes = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("accepted negative storage threshold")
	}
}

func TestOutboundLimitsConfiguration(t *testing.T) {
	cfg := &Config{Server: ServerConfig{Hostname: "mail.example.com"}, TLS: TLSConfig{Mode: "none"}, OutboundLimits: OutboundLimitsConfig{Enabled: true}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.OutboundLimits.MessagesPerHour != 100 || cfg.OutboundLimits.MaxRecipientsPerMessage != 100 || cfg.OutboundLimits.SuspensionMinutes != 60 {
		t.Fatalf("unexpected outbound defaults: %+v", cfg.OutboundLimits)
	}
	cfg.OutboundLimits.MessagesPerHour = 1000
	cfg.OutboundLimits.MessagesPerDay = 10
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "daily limits") {
		t.Fatalf("accepted inverted outbound limits: %v", err)
	}
	cfg.OutboundLimits.MessagesPerHour = 10
	cfg.OutboundLimits.MessagesPerDay = 100
	cfg.OutboundLimits.MaxRecipientsPerMessage = cfg.SMTP.MaxRecipients + 1
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "max_recipients_per_message") {
		t.Fatalf("accepted recipient limit above SMTP cap: %v", err)
	}
}
