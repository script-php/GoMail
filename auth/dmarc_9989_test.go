package auth

import (
	"net"
	"testing"
)

func TestDMARC9989DefaultsAndHistoricPct(t *testing.T) {
	previous := lookupTXT
	lookupTXT = func(name string) ([]string, error) {
		if name == "_dmarc.example.test" {
			return []string{"v=DMARC1; rua=mailto:reports@example.test; pct=0"}, nil
		}
		return nil, &net.DNSError{IsNotFound: true}
	}
	t.Cleanup(func() { lookupTXT = previous })
	got := CheckDMARC("example.test", SPFFail, "other.test", "fail", "")
	if got.Result != DMARCFail || got.Policy != PolicyNone {
		t.Fatalf("absent p must default to none: %+v", got)
	}
	lookupTXT = func(name string) ([]string, error) {
		if name == "_dmarc.example.test" {
			return []string{"v=DMARC1; p=reject; pct=0"}, nil
		}
		return nil, &net.DNSError{IsNotFound: true}
	}
	got = CheckDMARC("example.test", SPFFail, "other.test", "fail", "")
	if got.Result != DMARCFail || got.Policy != PolicyReject || got.PercentApply != 100 {
		t.Fatalf("historic pct must not sample enforcement: %+v", got)
	}
}

func TestDMARC9989NonexistentDomainAndTestingMode(t *testing.T) {
	previousTXT, previousExists := lookupTXT, lookupDMARCDomainExists
	lookupTXT = func(name string) ([]string, error) {
		if name == "_dmarc.example.test" {
			return []string{"v=DMARC1; p=reject; sp=quarantine; np=none; t=y"}, nil
		}
		return nil, &net.DNSError{IsNotFound: true}
	}
	lookupDMARCDomainExists = func(string) (bool, error) { return false, nil }
	t.Cleanup(func() { lookupTXT, lookupDMARCDomainExists = previousTXT, previousExists })
	got := CheckDMARC("missing.example.test", SPFFail, "other.test", "fail", "")
	if got.Result != DMARCFail || got.Policy != PolicyNone {
		t.Fatalf("NXDOMAIN must use np=none: %+v", got)
	}
	lookupDMARCDomainExists = func(string) (bool, error) { return true, nil }
	got = CheckDMARC("existing.example.test", SPFFail, "other.test", "fail", "")
	if got.Result != DMARCFail || got.Policy != PolicyNone {
		t.Fatalf("existing domain must use sp=quarantine, reduced by t=y: %+v", got)
	}
	lookupTXT = func(name string) ([]string, error) {
		if name == "_dmarc.example.test" {
			return []string{"v=DMARC1; p=reject; t=y"}, nil
		}
		return nil, &net.DNSError{IsNotFound: true}
	}
	got = CheckDMARC("example.test", SPFFail, "other.test", "fail", "")
	if got.Result != DMARCFail || got.Policy != PolicyQuarantine {
		t.Fatalf("t=y must lower reject to quarantine: %+v", got)
	}
}
