package mta_sts

import (
	"errors"
	"path/filepath"
	"testing"

	"gomail/store"
)

func TestPolicySurvivesProcessCacheLossAndFetchFailure(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "mail.db"), filepath.Join(t.TempDir(), "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	oldLookup, oldFetcher := lookupTXT, policyDocument
	defer func() { lookupTXT, policyDocument = oldLookup, oldFetcher; ClearPolicyCache() }()
	ClearPolicyCache()
	lookupTXT = func(string) ([]string, error) { return []string{"v=STSv1; id=first"}, nil }
	policyDocument = func(string) (*Policy, error) {
		return &Policy{Version: "STSv1", Mode: "enforce", MXHosts: []string{"mx.example.com"}, MaxAge: 3600}, nil
	}
	if policy, err := FetchPolicyWithStore("example.com", db); err != nil || policy == nil {
		t.Fatalf("initial fetch: %+v, %v", policy, err)
	}
	ClearPolicyCache() // Simulate a server restart.
	lookupTXT = func(string) ([]string, error) { return nil, errors.New("DNS unavailable") }
	policyDocument = func(string) (*Policy, error) { return nil, errors.New("HTTPS unavailable") }
	policy, err := FetchPolicyWithStore("example.com", db)
	if err != nil || policy == nil || policy.Mode != "enforce" {
		t.Fatalf("lost cached policy after restart: %+v, %v", policy, err)
	}
}
