package auth

import (
	"net"
	"strings"
	"testing"
)

func TestDMARCExactSubdomainUsesPNotSP(t *testing.T) {
	old := lookupTXT
	lookupTXT = func(name string) ([]string, error) {
		if name == "_dmarc.mail.example.com" {
			return []string{"v=DMARC1; p=reject; sp=none"}, nil
		}
		return nil, &net.DNSError{IsNotFound: true}
	}
	t.Cleanup(func() { lookupTXT = old })
	got := CheckDMARC("mail.example.com", SPFFail, "other.test", "fail", "")
	if got.Result != DMARCFail || got.Policy != PolicyReject {
		t.Fatalf("exact subdomain record must use p=: %+v", got)
	}
}

func TestDMARCTreeWalkUsesParentPolicyAndBoundary(t *testing.T) {
	old := lookupTXT
	lookupTXT = func(name string) ([]string, error) {
		switch name {
		case "_dmarc.mail.example.com":
			return []string{"v=DMARC1; p=reject; sp=quarantine; psd=n"}, nil
		case "_dmarc.example.com":
			return []string{"v=DMARC1; p=none"}, nil
		default:
			return nil, &net.DNSError{IsNotFound: true}
		}
	}
	t.Cleanup(func() { lookupTXT = old })
	got := CheckDMARC("news.mail.example.com", SPFFail, "other.test", "fail", "")
	if got.Result != DMARCFail || got.Policy != PolicyQuarantine {
		t.Fatalf("nearest organizational policy not applied: %+v", got)
	}
	got = CheckDMARC("news.mail.example.com", SPFPass, "bounce.mail.example.com", "fail", "")
	if got.Result != DMARCPass {
		t.Fatalf("same tree boundary did not align: %+v", got)
	}
	got = CheckDMARC("news.mail.example.com", SPFPass, "bounce.example.com", "fail", "")
	if got.Result != DMARCFail {
		t.Fatalf("psd=n boundary incorrectly aligned: %+v", got)
	}
}

func TestDMARCParentDNSFailureRemainsTempError(t *testing.T) {
	old := lookupTXT
	lookupTXT = func(name string) ([]string, error) {
		if name == "_dmarc.example.com" {
			return nil, &net.DNSError{IsTimeout: true, IsTemporary: true}
		}
		return nil, &net.DNSError{IsNotFound: true}
	}
	t.Cleanup(func() { lookupTXT = old })
	got := CheckDMARC("news.example.com", SPFFail, "other.test", "fail", "")
	if got.Result != DMARCTempError {
		t.Fatalf("parent timeout was treated as no policy: %+v", got)
	}
}

func TestDMARCExactPolicyDoesNotDependOnParentDNS(t *testing.T) {
	old := lookupTXT
	lookupTXT = func(name string) ([]string, error) {
		if name == "_dmarc.news.example.com" {
			return []string{"v=DMARC1; p=reject; aspf=s"}, nil
		}
		return nil, &net.DNSError{IsTimeout: true, IsTemporary: true}
	}
	t.Cleanup(func() { lookupTXT = old })
	got := CheckDMARC("news.example.com", SPFPass, "news.example.com", "fail", "")
	if got.Result != DMARCPass || got.Policy != PolicyReject {
		t.Fatalf("exact policy depended on unavailable parent: %+v", got)
	}
}

func TestDMARCPSDPolicyAndOrganizationBoundary(t *testing.T) {
	old := lookupTXT
	lookupTXT = func(name string) ([]string, error) {
		if name == "_dmarc.bank.example" {
			return []string{"v=DMARC1; p=reject; sp=quarantine; psd=y"}, nil
		}
		return nil, &net.DNSError{IsNotFound: true}
	}
	t.Cleanup(func() { lookupTXT = old })
	got := CheckDMARC("giant.bank.example", SPFPass, "mail.giant.bank.example", "fail", "")
	if got.Result != DMARCPass || got.Policy != PolicyQuarantine {
		t.Fatalf("PSD fallback or relaxed organization mismatch: %+v", got)
	}
	got = CheckDMARC("giant.bank.example", SPFPass, "mail.other.bank.example", "fail", "")
	if got.Result != DMARCFail || got.Policy != PolicyQuarantine {
		t.Fatalf("different organizations aligned across PSD: %+v", got)
	}
}

func TestDMARCTreeWalkBoundedToEightQueries(t *testing.T) {
	old := lookupTXT
	var queried []string
	lookupTXT = func(name string) ([]string, error) {
		queried = append(queried, name)
		return nil, &net.DNSError{IsNotFound: true}
	}
	t.Cleanup(func() { lookupTXT = old })
	_, err := dmarcTreeWalk("a.b.c.d.e.f.g.h.i.j.mail.example.com")
	if err != nil || len(queried) != 8 || queried[0] != "_dmarc.a.b.c.d.e.f.g.h.i.j.mail.example.com" || queried[1] != "_dmarc.g.h.i.j.mail.example.com" || !strings.HasSuffix(queried[7], "_dmarc.com") {
		t.Fatalf("wrong bounded walk: %v, %v", queried, err)
	}
}
