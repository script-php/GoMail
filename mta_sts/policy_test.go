package mta_sts

import (
	"errors"
	"testing"
	"time"
)

func TestParsePolicyValidation(t *testing.T) {
	valid := "version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400\n"
	p, err := ParsePolicy(valid)
	if err != nil || p.MaxAge != 86400 {
		t.Fatalf("%+v %v", p, err)
	}
	for _, bad := range []string{"version: STSv1\nmode: enforce\nmx: mx.example\n", "version: STSv1\nmode: enforce\nmax_age: 1\n", "version: STSv1\nversion: STSv1\nmode: none\nmax_age: 1\n", "# comment\nversion: STSv1\nmode: none\nmax_age: 1\n", "version: STSv1\nmode: enforce\nmx: *.example.com/\nmax_age: 1\n", "version: STSv1\nmode: enforce\nmx: mail_1.example.com\nmax_age: 1\n", "version: STSv1\nmode: enforce\nmx: foo.*.example.com\nmax_age: 1\n"} {
		if _, err := ParsePolicy(bad); err == nil {
			t.Errorf("accepted invalid policy %q", bad)
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
