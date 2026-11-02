package config

import "testing"

func TestSMTPRateLimitDefaults(t *testing.T) {
	cfg := &Config{Server: ServerConfig{Hostname: "mail.example.test"}, TLS: TLSConfig{Mode: "none"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.SMTP.RateLimit.ConnectionsPerMinute != 60 || cfg.SMTP.RateLimit.MessagesPerMinute != 30 {
		t.Fatalf("unexpected SMTP limits: %+v", cfg.SMTP.RateLimit)
	}
	cfg.SMTP.RateLimit.ConnectionsPerMinute = 12
	cfg.SMTP.RateLimit.MessagesPerMinute = 0
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.SMTP.RateLimit.ConnectionsPerMinute != 12 || cfg.SMTP.RateLimit.MessagesPerMinute != 30 {
		t.Fatalf("partial SMTP limits: %+v", cfg.SMTP.RateLimit)
	}
}
