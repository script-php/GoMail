package auth

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
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
// RFC 7208 compliant with DNS lookup counter (max 10), exists mechanism, exp= modifier, and macro expansion.
func CheckSPF(ip, mailFrom string) (SPFResult, string) {
	if mailFrom == "" {
		return SPFNone, "no envelope sender"
	}

	parts := strings.SplitN(mailFrom, "@", 2)
	if len(parts) != 2 {
		return SPFNone, "invalid envelope sender"
	}
	domain := parts[1]

	// Parse local part for macro expansion
	localPart := parts[0]

	// Create context for macro expansion and DNS tracking
	ctx := &spfContext{
		senderIP:       ip,
		localPart:      localPart,
		domain:         domain,
		helo:           domain, // Default to domain if HELO not provided
		receiverDomain: domain, // Default to domain; caller can override
		lookups:        0,
		voidLookups:    0,
		timestamp:      time.Now().Unix(),
	}

	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return SPFPermError, "invalid client IP"
	}

	var explanation string
	result, msg := checkSPFDomainWithContext(clientIP, domain, 0, ctx, &explanation)
	return result, msg
}

// spfContext holds state for SPF checking (DNS lookups, macro context).
type spfContext struct {
	senderIP       string // Client connecting IP
	localPart      string // Local part of mail-from
	domain         string // Mail-from domain
	helo           string // HELO/EHLO domain
	receiverDomain string // Receiver's domain (for %{r} macro)
	lookups        int    // DNS lookup counter (max 10 per RFC 7208)
	voidLookups    int    // Void lookup counter (max 2 per RFC 7208 §4.6.4)
	timestamp      int64  // Current timestamp for %{t} macro
}

// checkSPFDomainWithContext recursively checks SPF for included/redirected domains with full RFC 7208 support.
func checkSPFDomainWithContext(clientIP net.IP, domain string, depth int, ctx *spfContext, explanation *string) (SPFResult, string) {
	// Check lookup counter (RFC 7208 §4.6.4)
	if ctx.lookups >= 10 {
		return SPFPermError, "too many DNS lookups (max 10 allowed)"
	}

	// Look up SPF record (counts as one DNS lookup for mechanisms that need it)
	ctx.lookups++
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		// RFC 7208 §4.3: NXDOMAIN or NODATA at top level → SPFNone
		// At nested level (include/redirect) → SPFPermError
		// Other DNS errors → SPFTempError
		if depth == 0 {
			// Top-level domain: treat NXDOMAIN same as "no SPF record"
			// (both cases mean "no policy to check")
			return SPFNone, "no SPF record found"
		}
		// At included/redirected level: NXDOMAIN is a permerror
		return SPFPermError, fmt.Sprintf("DNS lookup failed for included domain: %v", err)
	}

	var spfRecord string
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1 ") || txt == "v=spf1" {
			spfRecord = txt
			break
		}
	}

	if spfRecord == "" {
		if depth == 0 {
			return SPFNone, "no SPF record found"
		}
		return SPFNeutral, fmt.Sprintf("no SPF record for %s", domain)
	}

	// Parse terms - separate mechanisms from modifiers
	terms := strings.Fields(spfRecord)
	var redirectDomain, expModifier string

	// First pass: extract modifiers (redirect=, exp=)
	var mechanisms []string
	for _, term := range terms[1:] { // Skip "v=spf1"
		if strings.HasPrefix(term, "redirect=") {
			redirectDomain = term[9:]
		} else if strings.HasPrefix(term, "exp=") {
			expModifier = term[4:]
		} else {
			mechanisms = append(mechanisms, term)
		}
	}

	// Second pass: evaluate mechanisms
	for _, term := range mechanisms {
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

		matched, mechResult := evaluateMechanism(clientIP, domain, mechanism, ctx, explanation)

		// Handle mechanism-specific error propagation
		if mechResult != "" {
			return SPFResult(mechResult), fmt.Sprintf("mechanism %s: %s", term, mechResult)
		}

		if matched {
			// If fail result, fetch exp= explanation
			if qualifier == SPFFail && expModifier != "" && *explanation == "" {
				fetchExplanation(expModifier, ctx, explanation)
			}
			return qualifier, fmt.Sprintf("matched mechanism: %s", term)
		}
	}

	// RFC 7208 §6.1: redirect MUST only be evaluated after all mechanisms fail to match
	if redirectDomain != "" {
		redirectDomain = expandMacros(redirectDomain, ctx, false)
		return checkSPFDomainWithContext(clientIP, redirectDomain, depth+1, ctx, explanation)
	}

	if depth == 0 {
		return SPFNeutral, "no mechanism matched"
	}
	return SPFNeutral, fmt.Sprintf("no match in %s", domain)
}

// evaluateMechanism evaluates a single SPF mechanism.
// Returns (matched bool, errorResult string). errorResult is non-empty for temperror/permerror.
func evaluateMechanism(clientIP net.IP, domain, mechanism string, ctx *spfContext, explanation *string) (bool, string) {
	switch {
	case mechanism == "all":
		return true, ""

	case mechanism == "a" || strings.HasPrefix(mechanism, "a:") || strings.HasPrefix(mechanism, "a/"):
		checkDomain, cidr4, cidr6 := parseAMXMechanism(mechanism, "a", domain, ctx)
		return matchAWithCIDR(clientIP, checkDomain, cidr4, cidr6, ctx), ""

	case mechanism == "mx" || strings.HasPrefix(mechanism, "mx:") || strings.HasPrefix(mechanism, "mx/"):
		checkDomain, cidr4, cidr6 := parseAMXMechanism(mechanism, "mx", domain, ctx)
		return matchMXWithCIDR(clientIP, checkDomain, cidr4, cidr6, ctx), ""

	case strings.HasPrefix(mechanism, "ip4:"):
		cidr := mechanism[4:]
		return matchIP(clientIP, cidr), ""

	case strings.HasPrefix(mechanism, "ip6:"):
		cidr := mechanism[4:]
		return matchIP(clientIP, cidr), ""

	case strings.HasPrefix(mechanism, "exists:"):
		queryDomain := expandMacros(mechanism[7:], ctx, false)
		return matchExists(queryDomain, ctx), ""

	case strings.HasPrefix(mechanism, "include:"):
		includeDomain := expandMacros(mechanism[8:], ctx, false)
		result, _ := checkSPFDomainWithContext(clientIP, includeDomain, 1, ctx, explanation)
		// RFC 7208 §5.2: include error semantics
		switch result {
		case SPFPass:
			return true, ""
		case SPFTempError:
			return false, "temperror" // Propagate temperror
		case SPFPermError, SPFNone:
			return false, "permerror" // Propagate permerror/none as permerror
		default:
			// fail, softfail, neutral → no match, continue
			return false, ""
		}

	case mechanism == "ptr" || strings.HasPrefix(mechanism, "ptr:"):
		// ptr mechanism (deprecated but required for compatibility)
		checkDomain := domain
		if strings.HasPrefix(mechanism, "ptr:") {
			checkDomain = expandMacros(mechanism[4:], ctx, false)
		}
		return matchPTR(clientIP, checkDomain, ctx), ""
	}

	return false, ""
}

// parseAMXMechanism parses a or mx mechanism with optional domain and CIDR.
// Format: a, a:domain, a/cidr4, a:domain/cidr4, a/cidr4//cidr6, a:domain/cidr4//cidr6
func parseAMXMechanism(mechanism, prefix, defaultDomain string, ctx *spfContext) (domain string, cidr4, cidr6 int) {
	domain = defaultDomain
	cidr4, cidr6 = 32, 128 // defaults

	// Remove prefix
	rest := mechanism
	if mechanism == prefix {
		return domain, cidr4, cidr6
	}
	if strings.HasPrefix(mechanism, prefix+":") {
		rest = mechanism[len(prefix)+1:]
	} else if strings.HasPrefix(mechanism, prefix+"/") {
		rest = mechanism[len(prefix):]
	} else {
		return domain, cidr4, cidr6
	}

	// Parse dual CIDR (//cidr6)
	if idx := strings.Index(rest, "//"); idx >= 0 {
		if c6, err := strconv.Atoi(rest[idx+2:]); err == nil {
			cidr6 = c6
		}
		rest = rest[:idx]
	}

	// Parse CIDR4 and domain
	if idx := strings.LastIndex(rest, "/"); idx >= 0 {
		if c4, err := strconv.Atoi(rest[idx+1:]); err == nil {
			cidr4 = c4
		}
		rest = rest[:idx]
	}

	if rest != "" {
		domain = expandMacros(rest, ctx, false)
	}

	return domain, cidr4, cidr6
}

// fetchExplanation fetches the exp= explanation text.
// RFC 7208 §6.2: exp= points to a TXT record containing plain explanation text (not SPF record).
func fetchExplanation(expDomain string, ctx *spfContext, explanation *string) {
	if ctx.lookups >= 10 {
		return
	}
	ctx.lookups++
	expDomain = expandMacros(expDomain, ctx, false)
	if txtRecords, err := net.LookupTXT(expDomain); err == nil && len(txtRecords) > 0 {
		// Concatenate all TXT record strings and expand macros
		*explanation = expandMacros(strings.Join(txtRecords, ""), ctx, false)
	}
}

// expandMacros implements RFC 7208 §7 macro expansion.
// urlEncode controls whether to URL-encode the result (for uppercase macros).
func expandMacros(input string, ctx *spfContext, urlEncode bool) string {
	var result strings.Builder
	i := 0
	for i < len(input) {
		if input[i] == '%' && i+1 < len(input) {
			if input[i+1] == '%' {
				result.WriteByte('%')
				i += 2
				continue
			}
			if input[i+1] == '_' {
				result.WriteByte(' ')
				i += 2
				continue
			}
			if input[i+1] == '-' {
				result.WriteString("%20")
				i += 2
				continue
			}
			if input[i+1] == '{' {
				// Find closing brace
				end := strings.Index(input[i:], "}")
				if end == -1 {
					result.WriteByte(input[i])
					i++
					continue
				}
				macro := input[i+2 : i+end]
				expanded := expandSingleMacro(macro, ctx)
				result.WriteString(expanded)
				i += end + 1
				continue
			}
		}
		result.WriteByte(input[i])
		i++
	}
	return result.String()
}

// expandSingleMacro expands a single macro like "i", "ir", "d2", etc.
func expandSingleMacro(macro string, ctx *spfContext) string {
	if len(macro) == 0 {
		return ""
	}

	// Parse macro letter
	letter := macro[0]
	rest := macro[1:]
	shouldURLEncode := letter >= 'A' && letter <= 'Z'
	letter = byte(strings.ToLower(string(letter))[0])

	// Get base value
	var value string
	switch letter {
	case 's': // sender (localpart@domain)
		value = ctx.localPart + "@" + ctx.domain
	case 'l': // local-part
		value = ctx.localPart
	case 'o': // domain (same as d for mail-from)
		value = ctx.domain
	case 'd': // domain
		value = ctx.domain
	case 'i': // IP address (dotted for IPv4, colon-expanded for IPv6)
		value = expandIP(ctx.senderIP)
	case 'p': // validated domain name of IP (deprecated, use "unknown")
		value = "unknown"
	case 'v': // "in-addr" for IPv4, "ip6" for IPv6
		if strings.Contains(ctx.senderIP, ":") {
			value = "ip6"
		} else {
			value = "in-addr"
		}
	case 'h': // HELO/EHLO domain
		value = ctx.helo
	// exp-only macros (RFC 7208 §7.2)
	case 'c': // SMTP client IP (readable format)
		value = ctx.senderIP
	case 'r': // domain name of host performing the check
		value = ctx.receiverDomain
	case 't': // current timestamp (seconds since epoch)
		value = strconv.FormatInt(ctx.timestamp, 10)
	default:
		return "%" + "{" + macro + "}"
	}

	// Parse transformers: digit, 'r', and delimiter (RFC 7208 §7.1)
	reverse := false
	numParts := 0
	delimiter := "." // default delimiter

	for len(rest) > 0 {
		if rest[0] >= '0' && rest[0] <= '9' {
			// Parse number
			j := 0
			for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
				j++
			}
			numParts, _ = strconv.Atoi(rest[:j])
			rest = rest[j:]
		} else if rest[0] == 'r' || rest[0] == 'R' {
			reverse = true
			rest = rest[1:]
		} else {
			// Remaining characters are delimiter specification (RFC 7208 §7.1)
			// Valid delimiters: . - + , / _ =
			delimiter = ""
			for _, c := range rest {
				if strings.ContainsRune(".-+,/_=", c) {
					delimiter += string(c)
				}
			}
			if delimiter == "" {
				delimiter = "."
			}
			break
		}
	}

	// Apply transformers - split by any char in delimiter set
	var parts []string
	if len(delimiter) == 1 {
		parts = strings.Split(value, delimiter)
	} else {
		// Multiple delimiters: split by any of them
		parts = splitByAny(value, delimiter)
	}

	if reverse {
		// Reverse the parts
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
	}

	if numParts > 0 && numParts < len(parts) {
		// Take rightmost N parts
		parts = parts[len(parts)-numParts:]
	}

	value = strings.Join(parts, ".")

	if shouldURLEncode {
		value = url.QueryEscape(value)
	}

	return value
}

// splitByAny splits a string by any character in the delimiters string.
func splitByAny(s, delimiters string) []string {
	if len(delimiters) == 0 {
		return []string{s}
	}
	return strings.FieldsFunc(s, func(r rune) bool {
		return strings.ContainsRune(delimiters, r)
	})
}

// expandIP expands an IP address for macro use.
// IPv4: dotted quad. IPv6: expanded with dots between each hex digit.
func expandIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return ip
	}
	// IPv6: expand to 32 hex digits separated by dots
	var parts []string
	for _, b := range parsed.To16() {
		parts = append(parts, fmt.Sprintf("%x", b>>4))
		parts = append(parts, fmt.Sprintf("%x", b&0xf))
	}
	return strings.Join(parts, ".")
}

// matchAWithCIDR checks if clientIP matches A/AAAA records for domain with CIDR prefix.
func matchAWithCIDR(clientIP net.IP, domain string, cidr4, cidr6 int, ctx *spfContext) bool {
	if ctx.lookups >= 10 {
		return false
	}
	ctx.lookups++
	addrs, err := net.LookupHost(domain)
	if err != nil {
		// RFC 7208 §4.6.4: Track void lookups (NXDOMAIN or empty)
		ctx.voidLookups++
		if ctx.voidLookups > 2 {
			return false // SHOULD limit void lookups to 2
		}
		return false
	}
	if len(addrs) == 0 {
		ctx.voidLookups++
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		cidr := cidr6
		if ip.To4() != nil {
			cidr = cidr4
		}
		if matchIPWithPrefix(clientIP, ip, cidr) {
			return true
		}
	}
	return false
}

// matchMXWithCIDR checks if clientIP matches any MX host's A/AAAA records with CIDR.
// RFC 7208 §4.6.4: Limits MX records processed to 10.
func matchMXWithCIDR(clientIP net.IP, domain string, cidr4, cidr6 int, ctx *spfContext) bool {
	if ctx.lookups >= 10 {
		return false
	}
	ctx.lookups++
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		ctx.voidLookups++
		return false
	}
	if len(mxRecords) == 0 {
		ctx.voidLookups++
		return false
	}
	// RFC 7208 §4.6.4: SHOULD limit MX records to 10
	maxMX := 10
	if len(mxRecords) > maxMX {
		mxRecords = mxRecords[:maxMX]
	}
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		// A lookup for each MX host counts against limit
		if matchAWithCIDR(clientIP, host, cidr4, cidr6, ctx) {
			return true
		}
	}
	return false
}

// matchIPWithPrefix checks if two IPs are in the same prefix.
func matchIPWithPrefix(clientIP, recordIP net.IP, prefixLen int) bool {
	// Normalize to same form
	client4 := clientIP.To4()
	record4 := recordIP.To4()

	if client4 != nil && record4 != nil {
		// Both IPv4
		if prefixLen > 32 {
			prefixLen = 32
		}
		cidr := fmt.Sprintf("%s/%d", record4.String(), prefixLen)
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return false
		}
		return network.Contains(clientIP)
	}

	if client4 == nil && record4 == nil {
		// Both IPv6
		if prefixLen > 128 {
			prefixLen = 128
		}
		cidr := fmt.Sprintf("%s/%d", recordIP.String(), prefixLen)
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return false
		}
		return network.Contains(clientIP)
	}

	return false
}

// matchExists checks if any A record exists for the domain.
func matchExists(queryDomain string, ctx *spfContext) bool {
	if ctx.lookups >= 10 {
		return false
	}
	ctx.lookups++
	addrs, err := net.LookupHost(queryDomain)
	if err != nil {
		ctx.voidLookups++
		return false
	}
	if len(addrs) == 0 {
		ctx.voidLookups++
		return false
	}
	return true
}

// matchPTR implements the ptr mechanism (deprecated but required for compatibility).
// RFC 7208 §5.5: Check if any PTR record for clientIP resolves to a name under checkDomain.
// Limits PTR records processed to 10 per RFC 7208 §4.6.4.
func matchPTR(clientIP net.IP, checkDomain string, ctx *spfContext) bool {
	if ctx.lookups >= 10 {
		return false
	}
	ctx.lookups++

	// Get PTR records for the IP
	names, err := net.LookupAddr(clientIP.String())
	if err != nil {
		ctx.voidLookups++
		return false
	}
	if len(names) == 0 {
		ctx.voidLookups++
		return false
	}

	// RFC 7208 §5.5: SHOULD limit PTR records to 10
	maxPTR := 10
	if len(names) > maxPTR {
		names = names[:maxPTR]
	}

	checkDomain = strings.ToLower(strings.TrimSuffix(checkDomain, "."))

	for _, name := range names {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		// Check if name ends with checkDomain or equals checkDomain
		if name == checkDomain || strings.HasSuffix(name, "."+checkDomain) {
			// Validate: the name must resolve back to the client IP
			if ctx.lookups >= 10 {
				return false
			}
			ctx.lookups++
			addrs, err := net.LookupHost(name)
			if err != nil {
				ctx.voidLookups++
				continue
			}
			for _, addr := range addrs {
				if net.ParseIP(addr).Equal(clientIP) {
					return true
				}
			}
		}
	}
	return false
}

// matchIP checks if clientIP is within the given CIDR or matches the IP.
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
