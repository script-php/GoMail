package auth

import (
	"fmt"
	"math/rand"
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// DMARCResult represents the outcome of a DMARC check.
type DMARCResult string

const (
	DMARCPass DMARCResult = "pass"
	DMARCFail DMARCResult = "fail"
	DMARCNone DMARCResult = "none"
)

// DMARCPolicy represents the action a domain requests for failed messages.
type DMARCPolicy string

const (
	PolicyNone       DMARCPolicy = "none"
	PolicyQuarantine DMARCPolicy = "quarantine"
	PolicyReject     DMARCPolicy = "reject"
)

// DMARCCheckResult holds the full result of a DMARC evaluation.
type DMARCCheckResult struct {
	Result       DMARCResult
	Policy       DMARCPolicy
	Details      string
	ReportMailto []string // rua= aggregate report recipients
	ForensicMail []string // ruf= forensic report recipients
	PercentApply int      // pct= percentage (0-100)
}

// CheckDMARC evaluates DMARC policy for a message given SPF and DKIM results.
// fromDomain is the domain in the From header (RFC5322.From).
// spfDomain is the domain from the envelope sender that SPF was checked against.
func CheckDMARC(fromDomain string, spfResult SPFResult, spfDomain string, dkimResult string, dkimDomain string) DMARCCheckResult {
	if fromDomain == "" {
		return DMARCCheckResult{
			Result:       DMARCNone,
			Policy:       PolicyNone,
			Details:      "no From domain",
			ReportMailto: nil,
			ForensicMail: nil,
			PercentApply: 100,
		}
	}

	// Look up DMARC record
	dmarcRecord, err := lookupDMARC(fromDomain)
	if err != nil || dmarcRecord == "" {
		return DMARCCheckResult{
			Result:       DMARCNone,
			Policy:       PolicyNone,
			Details:      "no DMARC record found",
			ReportMailto: nil,
			ForensicMail: nil,
			PercentApply: 100,
		}
	}

	// Parse DMARC tags
	tags := parseDMARCTags(dmarcRecord)

	// Determine policy: use sp= for subdomains, p= for organizational domain
	policy := PolicyNone
	isSubdomain := isSubdomainOfOrg(fromDomain)

	var policyTag string
	if isSubdomain && tags["sp"] != "" {
		// Subdomain has sp= policy
		policyTag = tags["sp"]
	} else {
		// Use main policy
		policyTag = tags["p"]
	}

	switch policyTag {
	case "reject":
		policy = PolicyReject
	case "quarantine":
		policy = PolicyQuarantine
	default:
		policy = PolicyNone
	}

	// DMARC alignment mode
	aspf := tags["aspf"] // "r" = relaxed (default), "s" = strict
	adkim := tags["adkim"]
	if aspf == "" {
		aspf = "r"
	}
	if adkim == "" {
		adkim = "r"
	}

	// Check SPF alignment
	spfAligned := false
	if spfResult == SPFPass {
		spfAligned = checkAlignment(fromDomain, spfDomain, aspf)
	}

	// Check DKIM alignment
	dkimAligned := false
	if dkimResult == "pass" {
		dkimAligned = checkAlignment(fromDomain, dkimDomain, adkim)
	}

	// DMARC passes if either SPF or DKIM is aligned and passes
	if spfAligned || dkimAligned {
		return DMARCCheckResult{
			Result:       DMARCPass,
			Policy:       policy,
			Details:      "aligned authentication passed",
			ReportMailto: parseReportAddresses(tags["rua"]),
			ForensicMail: parseReportAddresses(tags["ruf"]),
			PercentApply: 100,
		}
	}

	// Check pct= (percentage sampling) for failures: only apply policy to pct% of messages
	pct := 100
	if tags["pct"] != "" {
		pct = parsePct(tags["pct"])
		if !shouldApplyPolicy(pct) {
			// Randomly sampled out - report as pass to avoid applying policy
			return DMARCCheckResult{
				Result:       DMARCPass,
				Policy:       policy,
				Details:      fmt.Sprintf("failed auth but excluded by pct=%s sampling", tags["pct"]),
				ReportMailto: parseReportAddresses(tags["rua"]),
				ForensicMail: parseReportAddresses(tags["ruf"]),
				PercentApply: pct,
			}
		}
	}

	details := fmt.Sprintf("policy=%s; spf_aligned=%v; dkim_aligned=%v", policy, spfAligned, dkimAligned)
	return DMARCCheckResult{
		Result:       DMARCFail,
		Policy:       policy,
		Details:      details,
		ReportMailto: parseReportAddresses(tags["rua"]),
		ForensicMail: parseReportAddresses(tags["ruf"]),
		PercentApply: pct,
	}
}

// isSubdomainOfOrg returns true if domain is a subdomain of its organizational domain.
func isSubdomainOfOrg(domain string) bool {
	parts := strings.Split(domain, ".")
	return len(parts) > 2 // More than 2 labels means it's a subdomain
}

// parsePct parses the pct= tag value (percentage, 0-100).
// Returns 100 if invalid or not specified (default: apply to all).
func parsePct(pctStr string) int {
	if pctStr == "" {
		return 100
	}
	var pct int
	fmt.Sscanf(pctStr, "%d", &pct)
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct
}

// parseReportAddresses parses rua= or ruf= values into individual email addresses.
// Format: "mailto:address1@example.com,mailto:address2@example.com"
func parseReportAddresses(reportTag string) []string {
	if reportTag == "" {
		return nil
	}

	var addresses []string
	for _, part := range strings.Split(reportTag, ",") {
		part = strings.TrimSpace(part)
		// Remove "mailto:" prefix if present
		if strings.HasPrefix(part, "mailto:") {
			part = strings.TrimPrefix(part, "mailto:")
		}
		if part != "" {
			addresses = append(addresses, part)
		}
	}
	return addresses
}

// shouldApplyPolicy returns true if the message should have the policy applied
// based on the percentage sampling. Returns true with probability pct/100.
func shouldApplyPolicy(pct int) bool {
	if pct >= 100 {
		return true
	}
	if pct <= 0 {
		return false
	}
	return rand.Intn(100) < pct
}

// lookupDMARC looks up the DMARC TXT record for a domain.
// Checks _dmarc.domain first, then the organizational domain.
func lookupDMARC(domain string) (string, error) {
	// Try exact domain
	record, err := queryDMARC(domain)
	if err == nil && record != "" {
		return record, nil
	}

	// Try organizational domain (one level up)
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) == 2 {
		orgDomain := parts[1]
		record, err := queryDMARC(orgDomain)
		if err == nil && record != "" {
			return record, nil
		}
	}

	return "", fmt.Errorf("no DMARC record for %s", domain)
}

func queryDMARC(domain string) (string, error) {
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := net.LookupTXT(dmarcDomain)
	if err != nil {
		return "", err
	}

	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=DMARC1") {
			return txt, nil
		}
	}
	return "", nil
}

func parseDMARCTags(record string) map[string]string {
	tags := make(map[string]string)
	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		idx := strings.IndexByte(part, '=')
		if idx == -1 {
			continue
		}
		key := strings.TrimSpace(part[:idx])
		value := strings.TrimSpace(part[idx+1:])
		tags[key] = value
	}
	return tags
}

// checkAlignment checks domain alignment in relaxed or strict mode.
func checkAlignment(fromDomain, authDomain, mode string) bool {
	fromDomain = strings.ToLower(fromDomain)
	authDomain = strings.ToLower(authDomain)

	if mode == "s" {
		// Strict: exact match
		return fromDomain == authDomain
	}

	// Relaxed: organizational domain must match
	return getOrgDomain(fromDomain) == getOrgDomain(authDomain)
}

// getOrgDomain returns the organizational domain using the public suffix list (RFC 7489 §3.2).
// This properly handles domains like co.uk, com.br, etc.
func getOrgDomain(domain string) string {
	// Use the public suffix list to determine the registrable domain
	registrableDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		// Fallback to last two labels if PSL lookup fails
		parts := strings.Split(domain, ".")
		if len(parts) <= 2 {
			return domain
		}
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return registrableDomain
}
