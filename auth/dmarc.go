package auth

import (
	"fmt"
	"net"
	"strings"
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
	Result  DMARCResult
	Policy  DMARCPolicy
	Details string
}

// CheckDMARC evaluates DMARC policy for a message given SPF and DKIM results.
// fromDomain is the domain in the From header (RFC5322.From).
// spfDomain is the domain from the envelope sender that SPF was checked against.
func CheckDMARC(fromDomain string, spfResult SPFResult, spfDomain string, dkimResult string, dkimDomain string) DMARCCheckResult {
	if fromDomain == "" {
		return DMARCCheckResult{DMARCNone, PolicyNone, "no From domain"}
	}

	// Look up DMARC record
	dmarcRecord, err := lookupDMARC(fromDomain)
	if err != nil || dmarcRecord == "" {
		return DMARCCheckResult{DMARCNone, PolicyNone, "no DMARC record found"}
	}

	// Parse DMARC tags
	tags := parseDMARCTags(dmarcRecord)

	policy := PolicyNone
	switch tags["p"] {
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
		return DMARCCheckResult{DMARCPass, policy, "aligned authentication passed"}
	}

	details := fmt.Sprintf("policy=%s; spf_aligned=%v; dkim_aligned=%v", policy, spfAligned, dkimAligned)
	return DMARCCheckResult{DMARCFail, policy, details}
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

// getOrgDomain returns the organizational domain (last two labels).
// This is simplified — a full implementation would use the public suffix list.
func getOrgDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
