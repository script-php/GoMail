package smtp

import (
	"net/mail"
	"testing"
)

func TestAuthorDomainRejectsAmbiguousFrom(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers mail.Header
		want    string
		fail    bool
	}{
		{"ordinary", mail.Header{"From": {"Alice <alice@Example.COM>"}}, "example.com", false},
		{"same-domain authors with sender", mail.Header{"From": {"Alice <alice@example.com>, Bob <bob@example.com>"}, "Sender": {"alice@example.com"}}, "example.com", false},
		{"missing", mail.Header{}, "", true},
		{"duplicate", mail.Header{"From": {"alice@example.com", "victim@other.test"}}, "", true},
		{"different domains", mail.Header{"From": {"alice@example.com, victim@other.test"}, "Sender": {"alice@example.com"}}, "", true},
		{"missing sender", mail.Header{"From": {"alice@example.com, bob@example.com"}}, "", true},
		{"malformed", mail.Header{"From": {"not-an-address"}}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := authorDomain(tc.headers)
			if got != tc.want || (err != nil) != tc.fail {
				t.Fatalf("authorDomain = %q, %v; want %q, fail=%v", got, err, tc.want, tc.fail)
			}
		})
	}
}

func TestSPFIdentityDomainForNullReversePath(t *testing.T) {
	if got := spfIdentityDomain("", "bounce.example.com."); got != "bounce.example.com" {
		t.Fatalf("null reverse-path SPF identity = %q", got)
	}
	if got := spfIdentityDomain("alice@example.com", "other.test"); got != "example.com" {
		t.Fatalf("MAIL FROM SPF identity = %q", got)
	}
}

func TestReportEnvelopeFromDomainForNullReversePath(t *testing.T) {
	if got := reportEnvelopeFromDomain(""); got != "" {
		t.Fatalf("null reverse-path report envelope domain = %q", got)
	}
	if got := reportEnvelopeFromDomain("alice@example.com"); got != "example.com" {
		t.Fatalf("ordinary report envelope domain = %q", got)
	}
}
