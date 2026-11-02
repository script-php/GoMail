package auth

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"

	"gomail/logging"
)

// DMARCResult represents the outcome of a DMARC check.
type DMARCResult string

const (
	DMARCPass      DMARCResult = "pass"
	DMARCFail      DMARCResult = "fail"
	DMARCNone      DMARCResult = "none"
	DMARCTempError DMARCResult = "temperror"
	DMARCPermError DMARCResult = "permerror"
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
	PolicyDomain string // DNS owner of the policy applied to the author domain
	SPFAligned   bool
	DKIMAligned  bool
	Details      string
	ReportMailto []string // rua= aggregate report recipients
	ForensicMail []string // ruf= forensic report recipients
	PercentApply int      // pct= percentage (0-100)
}

// CheckDMARC evaluates DMARC policy for a message given SPF and DKIM results.
// fromDomain is the domain in the From header (RFC5322.From).
// spfDomain is the domain from the envelope sender that SPF was checked against.
func CheckDMARC(fromDomain string, spfResult SPFResult, spfDomain string, dkimResult string, dkimDomain string, otherVerifiedDKIMDomains ...string) DMARCCheckResult {
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

	// Keep the policy domain: an exact author-domain record uses p=, while a
	// parent record may apply sp=/np= to a subdomain.
	dmarcRecord, policyDomain, err := lookupDMARCPolicy(fromDomain)
	if err != nil || dmarcRecord == "" {
		result := DMARCNone
		details := "no DMARC record found"
		if err != nil && !errors.Is(err, errNoDMARC) {
			result = DMARCPermError
			details = err.Error()
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && (dnsErr.IsTimeout || dnsErr.IsTemporary) {
				result = DMARCTempError
			}
		}
		return DMARCCheckResult{
			Result:       result,
			Policy:       PolicyNone,
			Details:      details,
			ReportMailto: nil,
			ForensicMail: nil,
			PercentApply: 100,
		}
	}

	// Parse DMARC tags
	tags := parseDMARCTags(dmarcRecord)
	if tags["v"] != "DMARC1" || tags["p"] == "" || (tags["p"] != "none" && tags["p"] != "quarantine" && tags["p"] != "reject") {
		return DMARCCheckResult{Result: DMARCPermError, Policy: PolicyNone, Details: "invalid DMARC policy record", PercentApply: 100}
	}

	// Apply subdomain policy only when the record came from a parent.
	policy := PolicyNone
	isSubdomain := !strings.EqualFold(fromDomain, policyDomain)

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
	var alignmentErr error
	if spfResult == SPFPass {
		spfAligned, alignmentErr = checkDMARCAlignment(fromDomain, spfDomain, aspf)
	}

	// Check DKIM alignment
	dkimAligned := false
	if dkimResult == "pass" {
		for _, domain := range append([]string{dkimDomain}, otherVerifiedDKIMDomains...) {
			aligned, err := checkDMARCAlignment(fromDomain, domain, adkim)
			if err != nil {
				alignmentErr = err
				continue
			}
			if aligned {
				dkimAligned = true
				break
			}
		}
	}

	// DMARC passes if either SPF or DKIM is aligned and passes
	if spfAligned || dkimAligned {
		return DMARCCheckResult{
			Result:       DMARCPass,
			Policy:       policy,
			PolicyDomain: policyDomain,
			SPFAligned:   spfAligned,
			DKIMAligned:  dkimAligned,
			Details:      "aligned authentication passed",
			ReportMailto: parseReportAddresses(tags["rua"]),
			ForensicMail: parseReportAddresses(tags["ruf"]),
			PercentApply: 100,
		}
	}
	if alignmentErr != nil {
		return dmarcLookupError(alignmentErr)
	}

	// Check pct= (percentage sampling) for failures: only apply policy to pct% of messages
	pct := 100
	if tags["pct"] != "" {
		pct = parsePct(tags["pct"])
		if !shouldApplyPolicy(pct) {
			// Sampling changes requested disposition, never authentication.
			return DMARCCheckResult{
				Result:       DMARCFail,
				Policy:       PolicyNone,
				PolicyDomain: policyDomain,
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
		PolicyDomain: policyDomain,
		Details:      details,
		ReportMailto: parseReportAddresses(tags["rua"]),
		ForensicMail: parseReportAddresses(tags["ruf"]),
		PercentApply: pct,
	}
}

// isSubdomainOfOrg returns true if domain is a subdomain of its organizational domain.
func isSubdomainOfOrg(domain string) bool {
	return !strings.EqualFold(strings.TrimSuffix(domain, "."), getOrgDomain(domain))
}

// parsePct parses the pct= tag value (percentage, 0-100).
// Returns 100 if invalid or not specified (default: apply to all).
func parsePct(pctStr string) int {
	if pctStr == "" {
		return 100
	}
	pct, err := strconv.Atoi(pctStr)
	if err != nil {
		return 100
	}
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

type dmarcTreeRecord struct {
	domain string
	record string
	psd    string
}

// dmarcTreeWalk performs at most eight lookups, including the starting name.
// RFC 9989 skips intermediate labels for an author name deeper than eight.
func dmarcTreeWalk(domain string) ([]dmarcTreeRecord, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	labels := strings.Split(domain, ".")
	if domain == "" || len(labels) == 0 {
		return nil, errNoDMARC
	}
	var records []dmarcTreeRecord
	index := 0
	for queries := 0; index < len(labels) && queries < 8; queries++ {
		name := strings.Join(labels[index:], ".")
		record, err := queryDMARC(name)
		if err == nil {
			psd := parseDMARCTags(record)["psd"]
			records = append(records, dmarcTreeRecord{name, record, psd})
			if psd == "n" || psd == "y" {
				break
			}
		} else if !errors.Is(err, errNoDMARC) && !errors.Is(err, errMultipleDMARC) {
			var dnsErr *net.DNSError
			if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
				return nil, err
			}
		}
		if index == 0 && len(labels) > 8 {
			index = len(labels) - 7
		} else {
			index++
		}
	}
	return records, nil
}

func dmarcOrgDomain(start string, records []dmarcTreeRecord) string {
	start = strings.ToLower(strings.TrimSuffix(start, "."))
	for _, record := range records {
		switch record.psd {
		case "n":
			return record.domain
		case "y":
			if record.domain == start {
				return start
			}
			labels := strings.Split(start, ".")
			psdLabels := strings.Split(record.domain, ".")
			if len(labels) > len(psdLabels) {
				return strings.Join(labels[len(labels)-len(psdLabels)-1:], ".")
			}
		}
	}
	if len(records) > 0 {
		return records[len(records)-1].domain
	}
	return start
}

// lookupDMARCPolicy returns the applicable record and its DNS owner.
func lookupDMARCPolicy(domain string) (string, string, error) {
	start := strings.ToLower(strings.TrimSuffix(domain, "."))
	if record, err := queryDMARC(start); err == nil {
		return record, start, nil
	} else if !errors.Is(err, errNoDMARC) && !errors.Is(err, errMultipleDMARC) {
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
			return "", "", err
		}
	}
	records, err := dmarcTreeWalk(domain)
	if err != nil {
		return "", "", err
	}
	if len(records) == 0 {
		return "", "", fmt.Errorf("%w for %s", errNoDMARC, domain)
	}
	if records[0].domain == start {
		return records[0].record, start, nil
	}
	org := dmarcOrgDomain(start, records)
	for _, record := range records {
		if record.domain == org {
			return record.record, record.domain, nil
		}
	}
	for _, record := range records {
		if record.psd == "y" {
			return record.record, record.domain, nil
		}
	}
	return "", "", fmt.Errorf("%w for %s", errNoDMARC, domain)
}

func checkDMARCAlignment(fromDomain, authDomain, mode string) (bool, error) {
	fromDomain = strings.ToLower(strings.TrimSuffix(fromDomain, "."))
	authDomain = strings.ToLower(strings.TrimSuffix(authDomain, "."))
	if authDomain == "" {
		return false, nil
	}
	if fromDomain == authDomain {
		return true, nil
	}
	if mode == "s" {
		return false, nil
	}
	fromRecords, err := dmarcTreeWalk(fromDomain)
	if err != nil {
		return false, err
	}
	authRecords, err := dmarcTreeWalk(authDomain)
	if err != nil {
		return false, err
	}
	return dmarcOrgDomain(fromDomain, fromRecords) == dmarcOrgDomain(authDomain, authRecords), nil
}

func dmarcLookupError(err error) DMARCCheckResult {
	result := DMARCPermError
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && (dnsErr.IsTimeout || dnsErr.IsTemporary) {
		result = DMARCTempError
	}
	return DMARCCheckResult{Result: result, Policy: PolicyNone, Details: err.Error(), PercentApply: 100}
}

var errNoDMARC = errors.New("no DMARC record")
var errMultipleDMARC = errors.New("multiple DMARC records")

func queryDMARC(domain string) (string, error) {
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := lookupTXT(dmarcDomain)
	if err != nil {
		logging.Debug(fmt.Sprintf("[auth] DMARC record not found for %s: %v", domain, err))
		return "", err
	}

	var found []string
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=DMARC1") {
			found = append(found, txt)
		}
	}
	if len(found) == 0 {
		return "", errNoDMARC
	}
	if len(found) > 1 {
		return "", fmt.Errorf("%w at %s", errMultipleDMARC, dmarcDomain)
	}
	return found[0], nil
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
