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

// AddSPF reports the SMTP identity actually evaluated by SPF. The reverse
// path's local part is not authenticated by the domain's SPF policy.
func (b *AuthResultsBuilder) AddSPF(result SPFResult, detail, mailFrom, helo string) {
	entry := fmt.Sprintf("spf=%s (%s)", result, authResultComment(detail))
	if mailFrom == "" {
		if identity := authResultValue(strings.TrimSuffix(helo, ".")); identity != "unknown" {
			entry += " smtp.helo=" + identity
		}
	} else if at := strings.LastIndexByte(mailFrom, '@'); at >= 0 {
		if identity := authResultValue(mailFrom[at+1:]); identity != "unknown" {
			entry += " smtp.mailfrom=" + identity
		}
	}
	b.results = append(b.results, entry)
}

// AddDKIM adds a DKIM result to the authentication results.
func (b *AuthResultsBuilder) AddDKIM(result, detail, domain, selector string) {
	entry := fmt.Sprintf("dkim=%s (%s)", result, authResultComment(detail))
	if domain != "" {
		entry += " header.d=" + authResultValue(domain)
	}
	if selector != "" {
		entry += " header.s=" + authResultValue(selector)
	}
	b.results = append(b.results, entry)
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
