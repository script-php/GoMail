package config

import (
	"strings"
	"testing"
)

func TestSMTPHostnameSyntax(t *testing.T) {
	for _, name := range []string{"localhost", "mail.example.test", "mx-2.example.test", "A.B"} {
		if !validSMTPHostname(name) {
			t.Errorf("valid SMTP hostname %q rejected", name)
		}
	}
	for _, name := range []string{"", "mail", "mail.example.test.", ".example.test", "mail..test", "-mail.example.test", "mail-.example.test", "mail_example.test", "mail.example.test\r\nRCPT TO:<victim@example.test>", strings.Repeat("a", 64) + ".example.test"} {
		if validSMTPHostname(name) {
			t.Errorf("invalid SMTP hostname %q accepted", name)
		}
		if name != "" {
			cfg := &Config{Server: ServerConfig{Hostname: name}}
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "server.hostname") {
				t.Errorf("configuration accepted invalid hostname %q: %v", name, err)
			}
		}
	}
}
