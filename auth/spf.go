package auth

import (
	"fmt"
	"net"
	"strings"
)

// SPFResult represents the outcome of an SPF check.
type SPFResult string

const (
	SPFPass      SPFResult = "pass"
	SPFFail      SPFResult = "fail"
	SPFSoftFail  SPFResult = "softfail"
	SPFNeutral   SPFResult = "neutral"
	SPFNone      SPFResult = "none"
	SPFTempError SPFResult = "temperror"
	SPFPermError SPFResult = "permerror"
)

// CheckSPF verifies the SPF record for the sender's domain against the connecting IP.
// This is a simplified SPF implementation covering the most common mechanisms.
func CheckSPF(ip, mailFrom string) (SPFResult, string) {
	if mailFrom == "" {
		return SPFNone, "no envelope sender"
	}

	parts := strings.SplitN(mailFrom, "@", 2)
	if len(parts) != 2 {
		return SPFNone, "invalid envelope sender"
	}
	domain := parts[1]

	// Look up SPF record
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return SPFTempError, fmt.Sprintf("DNS lookup failed: %v", err)
	}

	var spfRecord string
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1 ") || txt == "v=spf1" {
			spfRecord = txt
			break
		}
	}

	if spfRecord == "" {
		return SPFNone, "no SPF record found"
	}

	// Parse and evaluate mechanisms
	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return SPFPermError, "invalid client IP"
	}

	terms := strings.Fields(spfRecord)
	for _, term := range terms[1:] { // Skip "v=spf1"
		qualifier := SPFPass
		mechanism := term

		// Check for qualifier prefix
		switch {
		case strings.HasPrefix(mechanism, "+"):
			qualifier = SPFPass
			mechanism = mechanism[1:]
		case strings.HasPrefix(mechanism, "-"):
			qualifier = SPFFail
			mechanism = mechanism[1:]
		case strings.HasPrefix(mechanism, "~"):
			qualifier = SPFSoftFail
			mechanism = mechanism[1:]
		case strings.HasPrefix(mechanism, "?"):
			qualifier = SPFNeutral
			mechanism = mechanism[1:]
		}

		matched := false

		switch {
		case mechanism == "all":
			matched = true

		case mechanism == "a" || strings.HasPrefix(mechanism, "a:"):
			checkDomain := domain
			if strings.HasPrefix(mechanism, "a:") {
				checkDomain = mechanism[2:]
			}
			if matchA(clientIP, checkDomain) {
				matched = true
			}

		case mechanism == "mx" || strings.HasPrefix(mechanism, "mx:"):
			checkDomain := domain
			if strings.HasPrefix(mechanism, "mx:") {
				checkDomain = mechanism[3:]
			}
			if matchMX(clientIP, checkDomain) {
				matched = true
			}

		case strings.HasPrefix(mechanism, "ip4:"):
			cidr := mechanism[4:]
			if matchIP(clientIP, cidr) {
				matched = true
			}

		case strings.HasPrefix(mechanism, "ip6:"):
			cidr := mechanism[4:]
			if matchIP(clientIP, cidr) {
				matched = true
			}

		case strings.HasPrefix(mechanism, "include:"):
			includeDomain := mechanism[8:]
			result, _ := checkSPFDomain(clientIP, includeDomain, 0)
			if result == SPFPass {
				matched = true
			}

		case strings.HasPrefix(mechanism, "redirect="):
			redirectDomain := mechanism[9:]
			return checkSPFDomain(clientIP, redirectDomain, 0)
		}

		if matched {
			return qualifier, fmt.Sprintf("matched mechanism: %s", term)
		}
	}

	return SPFNeutral, "no mechanism matched"
}

// checkSPFDomain recursively checks SPF for included/redirected domains.
func checkSPFDomain(clientIP net.IP, domain string, depth int) (SPFResult, string) {
	if depth > 10 {
		return SPFPermError, "too many DNS lookups"
	}

	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return SPFTempError, fmt.Sprintf("DNS lookup for %s failed: %v", domain, err)
	}

	var spfRecord string
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1 ") || txt == "v=spf1" {
			spfRecord = txt
			break
		}
	}

	if spfRecord == "" {
		return SPFPermError, fmt.Sprintf("no SPF record for %s", domain)
	}

	terms := strings.Fields(spfRecord)
	for _, term := range terms[1:] {
		qualifier := SPFPass
		mechanism := term

		switch {
		case strings.HasPrefix(mechanism, "+"):
			qualifier = SPFPass
			mechanism = mechanism[1:]
		case strings.HasPrefix(mechanism, "-"):
			qualifier = SPFFail
			mechanism = mechanism[1:]
		case strings.HasPrefix(mechanism, "~"):
			qualifier = SPFSoftFail
			mechanism = mechanism[1:]
		case strings.HasPrefix(mechanism, "?"):
			qualifier = SPFNeutral
			mechanism = mechanism[1:]
		}

		matched := false
		switch {
		case mechanism == "all":
			matched = true
		case mechanism == "a" || strings.HasPrefix(mechanism, "a:"):
			checkDomain := domain
			if strings.HasPrefix(mechanism, "a:") {
				checkDomain = mechanism[2:]
			}
			if matchA(clientIP, checkDomain) {
				matched = true
			}
		case mechanism == "mx" || strings.HasPrefix(mechanism, "mx:"):
			checkDomain := domain
			if strings.HasPrefix(mechanism, "mx:") {
				checkDomain = mechanism[3:]
			}
			if matchMX(clientIP, checkDomain) {
				matched = true
			}
		case strings.HasPrefix(mechanism, "ip4:") || strings.HasPrefix(mechanism, "ip6:"):
			cidr := mechanism[4:]
			if matchIP(clientIP, cidr) {
				matched = true
			}
		case strings.HasPrefix(mechanism, "include:"):
			includeDomain := mechanism[8:]
			result, _ := checkSPFDomain(clientIP, includeDomain, depth+1)
			if result == SPFPass {
				matched = true
			}
		case strings.HasPrefix(mechanism, "redirect="):
			return checkSPFDomain(clientIP, mechanism[9:], depth+1)
		}

		if matched {
			return qualifier, fmt.Sprintf("matched: %s in %s", term, domain)
		}
	}

	return SPFNeutral, fmt.Sprintf("no match in %s", domain)
}

func matchA(clientIP net.IP, domain string) bool {
	addrs, err := net.LookupHost(domain)
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if net.ParseIP(addr).Equal(clientIP) {
			return true
		}
	}
	return false
}

func matchMX(clientIP net.IP, domain string) bool {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return false
	}
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		if matchA(clientIP, host) {
			return true
		}
	}
	return false
}

func matchIP(clientIP net.IP, cidr string) bool {
	// If no prefix length, add default
	if !strings.Contains(cidr, "/") {
		if clientIP.To4() != nil {
			cidr += "/32"
		} else {
			cidr += "/128"
		}
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(clientIP)
}
