package mta_sts

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Policy represents an MTA-STS policy.
type Policy struct {
	Version string
	Mode    string // "enforce", "testing", or "none"
	MXHosts []string
	MaxAge  int // Seconds
}

const maxPolicyAgeSeconds = 31557600 // RFC 8461: at most one year.

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
				continue
			}
			seen[key] = true
			policy.Version = value
		case "mode":
			if seen[key] {
				continue
			}
			seen[key] = true
			policy.Mode = value
		case "mx":
			if !validMXPattern(value) {
				return nil, fmt.Errorf("invalid mx pattern %q", value)
			}
			policy.MXHosts = append(policy.MXHosts, value)
		case "max_age":
			if seen[key] {
				continue
			}
			seen[key] = true
			// RFC 8461 requires 1 to 10 ASCII decimal digits.
			if len(value) == 0 || len(value) > 10 {
				return nil, fmt.Errorf("invalid max_age: %s", value)
			}
			for i := 0; i < len(value); i++ {
				if value[i] < '0' || value[i] > '9' {
					return nil, fmt.Errorf("invalid max_age: %s", value)
				}
			}
			if age, err := strconv.Atoi(value); err == nil && age <= maxPolicyAgeSeconds {
				policy.MaxAge = age
			} else {
				return nil, fmt.Errorf("invalid max_age: %s", value)
			}
		default:
			// Unknown extensions are ignored only when syntactically valid.
			if !validSTSFieldName(key) || !validPolicyExtensionValue(value) {
				return nil, fmt.Errorf("invalid policy extension %q", key)
			}
		}
	}

	if !seen["max_age"] {
		return nil, fmt.Errorf("policy has no max_age")
	}
	if err := policy.validate(); err != nil {
		return nil, err
	}

	return policy, nil
}

func validPolicyExtensionValue(value string) bool {
	if value == "" || !utf8.ValidString(value) || value[0] == ' ' || value[len(value)-1] == ' ' {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < ' ' || value[i] == 0x7f {
			return false
		}
	}
	return true
}

func (policy *Policy) validate() error {
	if policy.Version != "STSv1" {
		return fmt.Errorf("unsupported policy version: %s", policy.Version)
	}
	if policy.Mode != "enforce" && policy.Mode != "testing" && policy.Mode != "none" {
		return fmt.Errorf("invalid mode: %s", policy.Mode)
	}
	if policy.MaxAge < 0 || policy.MaxAge > maxPolicyAgeSeconds {
		return fmt.Errorf("invalid max_age: %d", policy.MaxAge)
	}
	if policy.Mode != "none" && len(policy.MXHosts) == 0 {
		return fmt.Errorf("policy has no MX hosts")
	}
	for _, host := range policy.MXHosts {
		if !validMXPattern(host) {
			return fmt.Errorf("invalid mx pattern %q", host)
		}
	}
	return nil
}

func validMXPattern(pattern string) bool {
	if strings.HasPrefix(pattern, "*.") {
		pattern = pattern[2:]
	}
	if pattern == "" || len(pattern) > 253 {
		return false
	}
	for _, label := range strings.Split(pattern, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !asciiAlphanumeric(c) && c != '-' {
				return false
			}
		}
	}
	return true
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
