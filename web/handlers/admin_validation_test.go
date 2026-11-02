package handlers

import "testing"

func TestValidateAccountEmail(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		domain  string
		valid   bool
	}{
		{name: "matching domain", address: "alice@example.com", domain: "example.com", valid: true},
		{name: "case insensitive domain", address: "alice@example.com", domain: "EXAMPLE.COM", valid: true},
		{name: "wrong domain", address: "alice@other.example", domain: "example.com"},
		{name: "display name", address: "Alice <alice@example.com>", domain: "example.com"},
		{name: "missing local part", address: "@example.com", domain: "example.com"},
		{name: "multiple addresses", address: "alice@example.com,bob@example.com", domain: "example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAccountEmail(tc.address, tc.domain)
			if (err == nil) != tc.valid {
				t.Fatalf("validateAccountEmail(%q, %q) error = %v, valid=%v", tc.address, tc.domain, err, tc.valid)
			}
		})
	}
}
