package config

import "testing"

func TestMailClientsDisabledByDefault(t *testing.T) {
	cfg := &Config{Server: ServerConfig{Hostname: "mail.example.com"}, TLS: TLSConfig{Mode: "none"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Clients.Enabled || cfg.Clients.IMAP.IsEnabled(cfg.Clients.Enabled) || cfg.Clients.POP3.IsEnabled(cfg.Clients.Enabled) || cfg.Clients.Submission.IsEnabled(cfg.Clients.Enabled) {
		t.Fatal("mail-client listeners must be disabled by default")
	}
	if cfg.Clients.IMAP.ListenAddr != ":993" || cfg.Clients.POP3.ListenAddr != ":995" || cfg.Clients.Submission.ListenAddr != ":587" {
		t.Fatalf("unexpected defaults: IMAP=%q POP3=%q submission=%q", cfg.Clients.IMAP.ListenAddr, cfg.Clients.POP3.ListenAddr, cfg.Clients.Submission.ListenAddr)
	}
}

func TestIMAPMustBeExplicitlyEnabled(t *testing.T) {
	cfg := &Config{Server: ServerConfig{Hostname: "mail.example.com"}, TLS: TLSConfig{Mode: "none"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Clients.IMAP.IsEnabled(true) {
		t.Fatal("IMAP became enabled without its explicit service switch")
	}
}

func TestMailClientsRequireTLS(t *testing.T) {
	cfg := &Config{Server: ServerConfig{Hostname: "mail.example.com"}, TLS: TLSConfig{Mode: "none"}, Clients: MailClientsConfig{Enabled: true}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("enabled mail-client listeners were accepted without TLS")
	}
}
