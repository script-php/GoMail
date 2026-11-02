package config

import "testing"

func TestOperationalSenderDefaultsAndValidation(t *testing.T) {
	s := ServerConfig{Hostname: "mail.example.test", Domain: "example.test"}
	if got := s.TLSReportSenderAddress(); got != "noreply-smtp-tls-reporting@example.test" {
		t.Fatal(got)
	}
	if got := s.DSNSenderAddress(); got != "Mailer-Daemon@example.test" {
		t.Fatal(got)
	}
	for _, address := range []string{"bad\r\nBcc: victim@example.test", "other@external.test", "Name <sender@example.test>"} {
		if err := validateOperationalSender("sender", address, s.Domain); err == nil {
			t.Fatalf("accepted %q", address)
		}
	}
	if err := validateOperationalSender("sender", "reports@example.test", s.Domain); err != nil {
		t.Fatal(err)
	}
}
