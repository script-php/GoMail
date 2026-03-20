package mta_sts

import (
	"fmt"
	"time"
)

// Policy represents an MTA-STS policy.
type Policy struct {
	Version  string
	Mode     string // "enforce", "testing", or "none"
	MXHosts  []string
	MaxAge   int // Seconds
}

// DefaultPolicy creates a standard MTA-STS policy for the given domain.
func DefaultPolicy(hostname string) *Policy {
	return &Policy{
		Version: "STSv1",
		Mode:    "enforce",
		MXHosts: []string{hostname},
		MaxAge:  86400, // 24 hours
	}
}

// String renders the policy as the text format served at /.well-known/mta-sts.txt.
func (p *Policy) String() string {
	result := fmt.Sprintf("version: %s\n", p.Version)
	result += fmt.Sprintf("mode: %s\n", p.Mode)
	for _, mx := range p.MXHosts {
		result += fmt.Sprintf("mx: %s\n", mx)
	}
	result += fmt.Sprintf("max_age: %d\n", p.MaxAge)
	return result
}

// DNSRecord returns the _mta-sts TXT record value to publish in DNS.
func (p *Policy) DNSRecord(domain string) string {
	// id should change when policy changes; using timestamp
	id := fmt.Sprintf("%d", time.Now().Unix())
	return fmt.Sprintf("v=STSv1; id=%s", id)
}
