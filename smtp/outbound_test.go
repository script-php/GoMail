package smtp

import (
	"bytes"
	"testing"

	"gomail/dns"
	"gomail/mta_sts"
)

func TestWriteSMTPDataDotTransparency(t *testing.T) {
	var out bytes.Buffer
	if err := writeSMTPData(&out, []byte("Subject: test\r\n\r\none\r\n.\r\n..two\r\nlast")); err != nil {
		t.Fatal(err)
	}
	want := "Subject: test\r\n\r\none\r\n..\r\n...two\r\nlast\r\n.\r\n"
	if out.String() != want {
		t.Fatalf("got %q want %q", out.String(), want)
	}
}

func TestTLSReportEventsDescribeAppliedPolicies(t *testing.T) {
	sts := &mta_sts.Policy{Version: "STSv1", Mode: "enforce", MXHosts: []string{"*.example.net"}, MaxAge: 86400}
	dane := dns.TLSAResult{Authenticated: true, Records: []dns.TLSARecord{{Usage: 3, Selector: 1, MatchingType: 1, CertData: "aabb"}}}
	events := tlsReportEvents("example.net", "mx.example.net.", nil, sts, dane)
	if len(events) != 2 {
		t.Fatalf("got %d events, want STS and TLSA", len(events))
	}
	if events[0].PolicyType != "sts" || events[0].PolicyString[2] != "mx: *.example.net" {
		t.Fatalf("bad STS event: %+v", events[0])
	}
	if events[1].PolicyType != "tlsa" || events[1].PolicyString[0] != "3 1 1 aabb" || events[1].PolicyDomain != "mx.example.net" {
		t.Fatalf("bad TLSA event: %+v", events[1])
	}

	plain := tlsReportEvents("example.net", "mx.example.net", nil, nil, dns.TLSAResult{})
	if len(plain) != 1 || plain[0].PolicyType != "no-policy-found" {
		t.Fatalf("bad no-policy event: %+v", plain)
	}
}
func TestSMTPUTF8Requirement(t *testing.T) {
	if requiresSMTPUTF8("a@example", "b@example", []byte("Subject: ascii\r\n\r\ncafé")) {
		t.Fatal("UTF-8 body alone incorrectly requires SMTPUTF8")
	}
	if !requiresSMTPUTF8("a@example", "b@example", []byte("Subject: café\r\n\r\nbody")) {
		t.Fatal("UTF-8 header did not require SMTPUTF8")
	}
}

func TestMatchSTSMX(t *testing.T) {
	tests := []struct {
		host, pattern string
		want          bool
	}{{"mx.example.com", "mx.example.com", true}, {"a.example.com", "*.example.com", true}, {"a.b.example.com", "*.example.com", false}, {"example.com", "*.example.com", false}}
	for _, tc := range tests {
		if got := matchSTSMX(tc.host, tc.pattern); got != tc.want {
			t.Errorf("matchSTSMX(%q,%q)=%v", tc.host, tc.pattern, got)
		}
	}
}
