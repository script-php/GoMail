package delivery

import "testing"

func TestDeliveryFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		message   string
		permanent bool
	}{
		{"MX lookup: temporary DNS failure", false},
		{"dial tcp: connection refused", false},
		{"remote: 450 mailbox busy", false},
		{"remote: 499 temporary error", false},
		{"remote: 550 user unknown", true},
		{"remote: 503 bad command sequence", true},
		{"remote: 599 permanent error", true},
	} {
		if got := isPermanentFailure(extractSMTPCode(tc.message)); got != tc.permanent {
			t.Errorf("%q: permanent=%v", tc.message, got)
		}
	}
}
