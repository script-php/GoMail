package mta_sts

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestParsePolicyValidation(t *testing.T) {
	valid := "version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400\n"
	p, err := ParsePolicy(valid)
	if err != nil || p.MaxAge != 86400 {
		t.Fatalf("%+v %v", p, err)
	}
	for _, bad := range []string{"version: STSv1\nmode: enforce\nmx: mx.example\n", "version: STSv1\nmode: enforce\nmax_age: 1\n", "# comment\nversion: STSv1\nmode: none\nmax_age: 1\n", "version: STSv1\nmode: enforce\nmx: *.example.com/\nmax_age: 1\n", "version: STSv1\nmode: enforce\nmx: mail_1.example.com\nmax_age: 1\n", "version: STSv1\nmode: enforce\nmx: foo.*.example.com\nmax_age: 1\n"} {
		if _, err := ParsePolicy(bad); err == nil {
			t.Errorf("accepted invalid policy %q", bad)
		}
	}
}

func TestParsePolicyKeepsFirstNonRepeatedFields(t *testing.T) {
	text := "version: STSv1\nmode: enforce\nmx: mx1.example.test\nmx: mx2.example.test\nmax_age: 3600\nversion: STSv1\nmode: none\nmax_age: 7200\n"
	policy, err := ParsePolicy(text)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Mode != "enforce" || policy.MaxAge != 3600 || len(policy.MXHosts) != 2 {
		t.Fatalf("repeated fields changed policy: %+v", policy)
	}
}

func TestParsePolicyMaxAgeRFC8461Bound(t *testing.T) {
	policy := func(age int) string {
		return fmt.Sprintf("version: STSv1\nmode: enforce\nmx: mx.example.test\nmax_age: %d\n", age)
	}
	if parsed, err := ParsePolicy(policy(maxPolicyAgeSeconds)); err != nil || parsed.MaxAge != maxPolicyAgeSeconds {
		t.Fatalf("maximum allowed age rejected: policy=%+v err=%v", parsed, err)
	}
	if _, err := ParsePolicy(policy(maxPolicyAgeSeconds + 1)); err == nil {
		t.Fatal("age above RFC 8461 maximum accepted")
	}
}

func TestParsePolicyMaxAgeSyntax(t *testing.T) {
	policy := func(age string) string {
		return "version: STSv1\nmode: enforce\nmx: mx.example.test\nmax_age: " + age + "\n"
	}
	for _, age := range []string{"", "+1", "-0", "1.0", "00000000000", "１"} {
		if _, err := ParsePolicy(policy(age)); err == nil {
			t.Errorf("accepted invalid max_age %q", age)
		}
	}
	if parsed, err := ParsePolicy(policy("0000000000")); err != nil || parsed.MaxAge != 0 {
		t.Fatalf("rejected valid ten-digit max_age: policy=%+v err=%v", parsed, err)
	}
}

func TestParsePolicyExtensionSyntax(t *testing.T) {
	base := "version: STSv1\nmode: enforce\nmx: mx.example.test\nmax_age: 3600\n"
	if _, err := ParsePolicy(base + "future_field: a value with UTF-8 café\n"); err != nil {
		t.Fatalf("rejected valid unknown extension: %v", err)
	}
	for _, extension := range []string{"bad?: value", "future: ", "future: bad\x01value", "future: bad\x7fvalue", "future: bad\xffvalue"} {
		if _, err := ParsePolicy(base + extension + "\n"); err == nil {
			t.Errorf("accepted malformed extension %q", extension)
		}
	}
}

func TestFetchPolicyRetainsValidCachedPolicyOnReplacementFailure(t *testing.T) {
	ClearPolicyCache()
	oldLookup, oldFetcher := lookupTXT, policyDocument
	defer func() {
		lookupTXT, policyDocument = oldLookup, oldFetcher
		ClearPolicyCache()
	}()
	policy := &Policy{Version: "STSv1", Mode: "enforce", MXHosts: []string{"mx.example.com"}, MaxAge: 3600}
	policyCache["example.com"] = &cachedPolicy{policy: policy, policyID: "old", expiresAt: time.Now().Add(time.Hour)}
	lookupTXT = func(string) ([]string, error) { return []string{"v=STSv1; id=new"}, nil }
	policyDocument = func(string) (*Policy, error) { return nil, errors.New("temporary HTTPS failure") }
	if got := FetchPolicy("example.com"); got != policy {
		t.Fatalf("valid cached policy was discarded: %#v", got)
	}
}
