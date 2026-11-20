package mta_sts

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

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

func TestInvalidPersistedPolicyIsNotApplied(t *testing.T) {
	for _, tc := range []struct {
		name, document string
		expiry         time.Duration
	}{
		{"invalid mode", `{"Version":"STSv1","Mode":"unknown","MXHosts":["mx.example.com"],"MaxAge":3600}`, time.Hour},
		{"invalid age", `{"Version":"STSv1","Mode":"enforce","MXHosts":["mx.example.com"],"MaxAge":31557601}`, time.Hour},
		{"expiry exceeds age", `{"Version":"STSv1","Mode":"enforce","MXHosts":["mx.example.com"],"MaxAge":3600}`, 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := store.Open(filepath.Join(t.TempDir(), "mail.db"), filepath.Join(t.TempDir(), "attachments"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := db.SaveMTASTSPolicy("example.com", "old", tc.document, time.Now().Add(tc.expiry)); err != nil {
				t.Fatal(err)
			}
			oldLookup, oldFetcher := lookupTXT, policyDocument
			defer func() { lookupTXT, policyDocument = oldLookup, oldFetcher; ClearPolicyCache() }()
			ClearPolicyCache()
			lookupTXT = func(string) ([]string, error) { return nil, errors.New("DNS unavailable") }
			policyDocument = func(string) (*Policy, error) { return nil, errors.New("HTTPS unavailable") }
			policy, err := FetchPolicyWithStore("example.com", db)
			if err != nil || policy != nil {
				t.Fatalf("invalid cached policy applied: policy=%+v err=%v", policy, err)
			}
		})
	}
}
