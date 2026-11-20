package auth

import (
	"net"
	"testing"
)

func TestDMARCVersionRecognition(t *testing.T) {
	for _, tc := range []struct {
		record string
		valid  bool
	}{
		{"v=DMARC1; p=reject", true},
		{"v = DMARC1 ; p=none", true},
		{"v=DMARC1", true},
		{"v=DMARC12; p=reject", false},
		{"v=DMARC1junk; p=reject", false},
		{"V=DMARC1; p=reject", false},
		{"p=reject; v=DMARC1", false},
		{" v=DMARC1; p=reject", false},
	} {
		if got := IsDMARCVersionRecord(tc.record); got != tc.valid {
			t.Errorf("%q: valid=%v, want %v", tc.record, got, tc.valid)
		}
	}
}

func TestDMARCIgnoresOtherVersionBeforeSelectingPolicy(t *testing.T) {
	previous := lookupTXT
	lookupTXT = func(name string) ([]string, error) {
		if name == "_dmarc.example.test" {
			return []string{"v=DMARC12; p=none", "v = DMARC1; p=reject"}, nil
		}
		return nil, &net.DNSError{IsNotFound: true}
	}
	t.Cleanup(func() { lookupTXT = previous })
	result := CheckDMARC("example.test", SPFFail, "other.test", "fail", "")
	if result.Result != DMARCFail || result.Policy != PolicyReject {
		t.Fatalf("wrong policy selected: %+v", result)
	}
}
