package auth

import (
	"fmt"
	"strings"
)

// AuthResultsBuilder constructs an Authentication-Results header per RFC 8601.
type AuthResultsBuilder struct {
	hostname string
	results  []string
}

// NewAuthResultsBuilder creates a builder for the given server hostname.
func NewAuthResultsBuilder(hostname string) *AuthResultsBuilder {
	return &AuthResultsBuilder{hostname: hostname}
}

// AddSPF adds an SPF result to the authentication results.
func (b *AuthResultsBuilder) AddSPF(result SPFResult, detail, domain string) {
	b.results = append(b.results, fmt.Sprintf(
		"spf=%s (%s) smtp.mailfrom=%s", result, authResultComment(detail), authResultValue(domain),
	))
}

// AddDKIM adds a DKIM result to the authentication results.
func (b *AuthResultsBuilder) AddDKIM(result, detail, domain, selector string) {
	b.results = append(b.results, fmt.Sprintf(
		"dkim=%s (%s) header.d=%s header.s=%s", result, authResultComment(detail), authResultValue(domain), authResultValue(selector),
	))
}

// AddDMARC adds a DMARC result to the authentication results.
func (b *AuthResultsBuilder) AddDMARC(result DMARCResult, detail, domain string) {
	b.results = append(b.results, fmt.Sprintf(
		"dmarc=%s (%s) header.from=%s", result, authResultComment(detail), authResultValue(domain),
	))
}

func authResultComment(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "(", "\\(")
	value = strings.ReplaceAll(value, ")", "\\)")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}
func authResultValue(value string) string {
	var out strings.Builder
	for _, r := range value {
		if r > 32 && r < 127 && !strings.ContainsRune("();=\\\"", r) {
			out.WriteRune(r)
		}
	}
	if out.Len() == 0 {
		return "unknown"
	}
	return out.String()
}

// Build constructs the full Authentication-Results header value.
func (b *AuthResultsBuilder) Build() string {
	if len(b.results) == 0 {
		return fmt.Sprintf("%s; none", b.hostname)
	}
	return fmt.Sprintf("%s;\r\n\t%s", b.hostname, strings.Join(b.results, ";\r\n\t"))
}
