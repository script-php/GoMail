package mta_sts

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type policyTransport func(*http.Request) (*http.Response, error)

func (f policyTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPolicyDocumentRejectsRedirectsAndWrongMediaType(t *testing.T) {
	previous := httpClient
	t.Cleanup(func() { httpClient = previous })
	const validPolicy = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"
	for _, tc := range []struct {
		name, location, contentType string
		code                        int
	}{
		{"https redirect", "https://other.example/.well-known/mta-sts.txt", "text/plain", 302},
		{"http downgrade", "http://mta-sts.example.com/.well-known/mta-sts.txt", "text/plain", 302},
		{"html response", "", "text/html", 200},
		{"missing media type", "", "", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			httpClient = &http.Client{
				CheckRedirect: previous.CheckRedirect,
				Transport: policyTransport(func(r *http.Request) (*http.Response, error) {
					requests++
					return &http.Response{StatusCode: tc.code, Header: http.Header{"Location": []string{tc.location}, "Content-Type": []string{tc.contentType}}, Body: io.NopCloser(strings.NewReader(validPolicy)), Request: r}, nil
				}),
			}
			if _, err := fetchPolicyDocument("example.com"); err == nil {
				t.Fatal("expected policy retrieval to fail")
			}
			if requests != 1 {
				t.Fatalf("made %d requests; expected one", requests)
			}
		})
	}
	httpClient = &http.Client{Transport: policyTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}}, Body: io.NopCloser(strings.NewReader(validPolicy)), Request: r}, nil
	})}
	if _, err := fetchPolicyDocument("example.com"); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
}

func TestSTSTXTRecordMustBeUniqueAndValid(t *testing.T) {
	previous := lookupTXT
	t.Cleanup(func() { lookupTXT = previous })
	for _, tc := range []struct {
		name    string
		records []string
		want    string
	}{
		{"valid", []string{"unrelated TXT", "v=STSv1; id=Abc123;"}, "Abc123"},
		{"valid delimiter whitespace", []string{"v=STSv1 \t; id=abc"}, "abc"},
		{"multiple", []string{"v=STSv1; id=one", "v=STSv1; id=two"}, ""},
		{"bad version prefix ignored", []string{"v=STSv1evil; id=bad"}, ""},
		{"missing id", []string{"v=STSv1; other=value"}, ""},
		{"empty id", []string{"v=STSv1; id="}, ""},
		{"invalid id", []string{"v=STSv1; id=bad value"}, ""},
		{"long id", []string{"v=STSv1; id=" + strings.Repeat("x", 33)}, ""},
		{"duplicate id", []string{"v=STSv1; id=one; id=two"}, ""},
		{"invalid extension", []string{"v=STSv1; id=one; ext=has=equals"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookupTXT = func(string) ([]string, error) { return tc.records, nil }
			if got := fetchDNSTXTRecord("example.com"); got != tc.want {
				t.Fatalf("id=%q want %q", got, tc.want)
			}
		})
	}
}

func TestPolicyDocumentRejectsOversizedBody(t *testing.T) {
	previous := httpClient
	t.Cleanup(func() { httpClient = previous })
	validPrefix := "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"
	httpClient = &http.Client{Transport: policyTransport(func(r *http.Request) (*http.Response, error) {
		body := validPrefix + strings.Repeat("\n", 64*1024-len(validPrefix)+1)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	if _, err := fetchPolicyDocument("example.com"); err == nil {
		t.Fatal("oversized policy prefix was accepted")
	}
}
