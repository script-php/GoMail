package mta_sts

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Policy represents an MTA-STS policy.
type Policy struct {
	Version string
	Mode    string // "enforce", "testing", or "none"
	MXHosts []string
	MaxAge  int // Seconds
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

// ParsePolicy parses a policy from the text format served at /.well-known/mta-sts.txt
func ParsePolicy(text string) (*Policy, error) {
	policy := &Policy{
		MXHosts: []string{},
	}
	seen := map[string]bool{}

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid policy line %q", line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "version":
			if seen[key] {
				return nil, fmt.Errorf("duplicate version field")
			}
			seen[key] = true
			policy.Version = value
		case "mode":
			if seen[key] {
				return nil, fmt.Errorf("duplicate mode field")
			}
			seen[key] = true
			policy.Mode = value
		case "mx":
			policy.MXHosts = append(policy.MXHosts, value)
		case "max_age":
			if seen[key] {
				return nil, fmt.Errorf("duplicate max_age field")
			}
			seen[key] = true
			// Parse as int
			if age, err := strconv.Atoi(value); err == nil && age >= 0 {
				policy.MaxAge = age
			} else {
				return nil, fmt.Errorf("invalid max_age: %s", value)
			}
		}
	}

	// Validate required fields
	if policy.Version != "STSv1" {
		return nil, fmt.Errorf("unsupported policy version: %s", policy.Version)
	}
	if policy.Mode != "enforce" && policy.Mode != "testing" && policy.Mode != "none" {
		return nil, fmt.Errorf("invalid mode: %s", policy.Mode)
	}
	if !seen["max_age"] {
		return nil, fmt.Errorf("policy has no max_age")
	}
	if policy.Mode != "none" && len(policy.MXHosts) == 0 {
		return nil, fmt.Errorf("policy has no MX hosts")
	}

	return policy, nil
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
