package auth

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"gomail/logging"
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
	return CheckSPFWithHELO(ip, mailFrom, "")
}

// CheckSPFWithHELO evaluates the RFC5321.MailFrom identity, or the HELO
// identity for a null reverse-path as required for bounce messages.
func CheckSPFWithHELO(ip, mailFrom, helo string) (SPFResult, string) {
	if mailFrom == "" {
		if helo == "" {
			return SPFNone, "no envelope sender or HELO identity"
		}
		mailFrom = "postmaster@" + strings.TrimSuffix(helo, ".")
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
		helo:           helo,
		receiverDomain: domain, // Default to domain; caller can override
		lookups:        0,
		voidLookups:    0,
		timestamp:      time.Now().Unix(),
	}
	if ctx.helo == "" {
		ctx.helo = domain
	}

	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		logging.Warn(fmt.Sprintf("[auth] SPF: invalid client IP %s", ip))
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
	validatedName  string // Cached forward-confirmed reverse DNS name for %{p}
	validatedSet   bool
}

// checkSPFDomainWithContext recursively checks SPF for included/redirected domains with full RFC 7208 support.
func checkSPFDomainWithContext(clientIP net.IP, domain string, depth int, ctx *spfContext, explanation *string) (SPFResult, string) {
	// Check lookup counter (RFC 7208 §4.6.4)
	if ctx.lookups > 10 {
		return SPFPermError, "too many DNS lookups (max 10 allowed)"
	}

	txtRecords, err := lookupTXT(domain)
	if err != nil {
		// RFC 7208 §4.3: NXDOMAIN or NODATA at top level → SPFNone
		// At nested level (include/redirect) → SPFPermError
		// Other DNS errors → SPFTempError
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound && depth == 0 {
			// Top-level domain: treat NXDOMAIN same as "no SPF record"
			// (both cases mean "no policy to check")
			return SPFNone, "no SPF record found"
		}
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			recordSPFVoidLookup(ctx)
			return SPFPermError, fmt.Sprintf("included domain does not exist: %v", err)
		}
		return SPFTempError, fmt.Sprintf("temporary DNS lookup failure: %v", err)
	}

	var spfRecords []string
	for _, txt := range txtRecords {
		fields := strings.Fields(txt)
		if len(fields) > 0 && strings.EqualFold(fields[0], "v=spf1") {
			spfRecords = append(spfRecords, txt)
		}
	}
	if len(spfRecords) > 1 {
		return SPFPermError, "multiple SPF records found"
	}
	spfRecord := ""
	if len(spfRecords) == 1 {
		spfRecord = spfRecords[0]
	}

	if spfRecord == "" {
		if depth == 0 {
			return SPFNone, "no SPF record found"
		}
		return SPFPermError, fmt.Sprintf("no SPF record for included domain %s", domain)
	}

	// Parse terms - separate mechanisms from modifiers
	terms := strings.Fields(spfRecord)
	var redirectDomain, expModifier string

	// First pass: extract modifiers (redirect=, exp=)
	var mechanisms []string
	seenModifiers := make(map[string]bool)
	for _, term := range terms[1:] { // Skip "v=spf1"
		if i := strings.IndexByte(term, '='); i >= 0 {
			name, value := strings.ToLower(term[:i]), term[i+1:]
			if !validSPFModifierName(name) || value == "" {
				return SPFPermError, fmt.Sprintf("invalid or duplicate SPF modifier %q", term)
			}
			switch name {
			case "redirect":
				if seenModifiers[name] {
					return SPFPermError, "duplicate redirect modifier"
				}
				seenModifiers[name] = true
				if err := validateMacroString(value, false); err != nil {
					return SPFPermError, fmt.Sprintf("invalid redirect modifier: %v", err)
				}
				redirectDomain = value
			case "exp":
				if seenModifiers[name] {
					return SPFPermError, "duplicate exp modifier"
				}
				seenModifiers[name] = true
				if err := validateMacroString(value, false); err != nil {
					return SPFPermError, fmt.Sprintf("invalid exp modifier: %v", err)
				}
				expModifier = value
			default:
				// RFC 7208 section 6: unrecognized modifiers are ignored.
			}
			continue
		}
		mechanisms = append(mechanisms, term)
	}
	// RFC 7208 section 4.6 requires syntax validation of the complete record
	// before interpretation, even when an earlier mechanism would match.
	for _, term := range mechanisms {
		mechanism := strings.TrimLeft(term, "+-~?")
		if len(term)-len(mechanism) > 1 || mechanism == "" {
			return SPFPermError, fmt.Sprintf("invalid SPF mechanism %q", term)
		}
		if err := validateSPFMechanism(normalizeSPFMechanism(mechanism)); err != nil {
			return SPFPermError, err.Error()
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
		mechanism = normalizeSPFMechanism(mechanism)

		matched, mechResult := evaluateMechanism(clientIP, domain, mechanism, ctx, explanation)

		// Handle mechanism-specific error propagation
		if mechResult != "" {
			return SPFResult(mechResult), fmt.Sprintf("mechanism %s: %s", term, mechResult)
		}
		if ctx.lookups > 10 {
			return SPFPermError, "too many DNS lookups (max 10 allowed)"
		}
		if ctx.voidLookups > 2 {
			return SPFPermError, "too many void DNS lookups (max 2 allowed)"
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
		if ctx.lookups >= 10 {
			return SPFPermError, "too many DNS lookups (max 10 allowed)"
		}
		ctx.lookups++
		redirectDomain = expandMacros(redirectDomain, ctx, false)
		return checkSPFDomainWithContext(clientIP, redirectDomain, depth+1, ctx, explanation)
	}

	if depth == 0 {
		return SPFNeutral, "no mechanism matched"
	}
	return SPFNeutral, fmt.Sprintf("no match in %s", domain)
}

func normalizeSPFMechanism(mechanism string) string {
	end := strings.IndexAny(mechanism, ":/")
	if end < 0 {
		return strings.ToLower(mechanism)
	}
	return strings.ToLower(mechanism[:end]) + mechanism[end:]
}

func validSPFModifierName(name string) bool {
	if name == "" || (name[0] < 'a' || name[0] > 'z') {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// evaluateMechanism evaluates a single SPF mechanism.
// Returns (matched bool, errorResult string). errorResult is non-empty for temperror/permerror.
func evaluateMechanism(clientIP net.IP, domain, mechanism string, ctx *spfContext, explanation *string) (bool, string) {
	switch {
	case mechanism == "all":
		return true, ""

	case mechanism == "a" || strings.HasPrefix(mechanism, "a:") || strings.HasPrefix(mechanism, "a/"):
		checkDomain, cidr4, cidr6 := parseAMXMechanism(mechanism, "a", domain, ctx)
		return matchAWithCIDR(clientIP, checkDomain, cidr4, cidr6, ctx, true)

	case mechanism == "mx" || strings.HasPrefix(mechanism, "mx:") || strings.HasPrefix(mechanism, "mx/"):
		checkDomain, cidr4, cidr6 := parseAMXMechanism(mechanism, "mx", domain, ctx)
		return matchMXWithCIDR(clientIP, checkDomain, cidr4, cidr6, ctx)

	case strings.HasPrefix(mechanism, "ip4:"):
		cidr := mechanism[4:]
		return matchIP(clientIP, cidr), ""

	case strings.HasPrefix(mechanism, "ip6:"):
		cidr := mechanism[4:]
		return matchIP(clientIP, cidr), ""

	case strings.HasPrefix(mechanism, "exists:"):
		queryDomain := expandMacros(mechanism[7:], ctx, false)
		return matchExists(queryDomain, ctx)

	case strings.HasPrefix(mechanism, "include:"):
		if ctx.lookups >= 10 {
			return false, "permerror"
		}
		ctx.lookups++
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
		return matchPTR(clientIP, checkDomain, ctx)
	}

	return false, "permerror"
}

func validateSPFMechanism(mechanism string) error {
	base := mechanism
	if i := strings.IndexAny(base, ":/"); i >= 0 {
		base = base[:i]
	}
	switch base {
	case "all", "a", "mx", "ip4", "ip6", "exists", "include", "ptr":
	default:
		return fmt.Errorf("unknown SPF mechanism %q", mechanism)
	}
	if base == "all" && mechanism != "all" {
		return fmt.Errorf("invalid all mechanism")
	}
	if base == "ip4" || base == "ip6" {
		value := strings.TrimPrefix(mechanism, base+":")
		if value == "" {
			return fmt.Errorf("empty %s mechanism", base)
		}
		if strings.Contains(value, "/") {
			if _, _, err := net.ParseCIDR(value); err != nil {
				return fmt.Errorf("invalid %s mechanism", base)
			}
		} else {
			ip := net.ParseIP(value)
			if ip == nil || (base == "ip4" && ip.To4() == nil) || (base == "ip6" && ip.To4() != nil) {
				return fmt.Errorf("invalid %s mechanism", base)
			}
		}
	}
	if base == "include" || base == "exists" {
		if !strings.HasPrefix(mechanism, base+":") || len(mechanism) == len(base)+1 {
			return fmt.Errorf("invalid %s mechanism", base)
		}
		if err := validateMacroString(strings.TrimPrefix(mechanism, base+":"), false); err != nil {
			return fmt.Errorf("invalid %s domain-spec: %w", base, err)
		}
	}
	if base == "ptr" && mechanism != "ptr" {
		if !strings.HasPrefix(mechanism, "ptr:") || len(mechanism) == len("ptr:") {
			return fmt.Errorf("invalid ptr mechanism")
		}
		if err := validateMacroString(strings.TrimPrefix(mechanism, "ptr:"), false); err != nil {
			return fmt.Errorf("invalid ptr domain-spec: %w", err)
		}
	}
	if base == "a" || base == "mx" {
		if err := validateAMXMechanism(mechanism, base); err != nil {
			return err
		}
	}
	return nil
}

func validateAMXMechanism(mechanism, prefix string) error {
	rest := strings.TrimPrefix(mechanism, prefix)
	if rest == "" {
		return nil
	}
	if rest[0] == ':' {
		rest = rest[1:]
		if rest == "" || rest[0] == '/' {
			return fmt.Errorf("invalid %s mechanism", prefix)
		}
	} else if rest[0] != '/' {
		return fmt.Errorf("invalid %s mechanism", prefix)
	}
	if i := strings.Index(rest, "//"); i >= 0 {
		if strings.Contains(rest[i+2:], "/") || !validPrefix(rest[i+2:], 128) {
			return fmt.Errorf("invalid %s IPv6 CIDR", prefix)
		}
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		if !validPrefix(rest[i+1:], 32) {
			return fmt.Errorf("invalid %s IPv4 CIDR", prefix)
		}
		rest = rest[:i]
	}
	if strings.Contains(rest, "/") {
		return fmt.Errorf("invalid %s mechanism", prefix)
	}
	if rest != "" {
		if err := validateMacroString(rest, false); err != nil {
			return fmt.Errorf("invalid %s domain-spec: %w", prefix, err)
		}
	}
	return nil
}

func validPrefix(value string, max int) bool {
	n, err := strconv.Atoi(value)
	return err == nil && n >= 0 && n <= max
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
	expDomain = expandMacros(expDomain, ctx, false)
	if txtRecords, err := lookupTXT(expDomain); err == nil && len(txtRecords) > 0 {
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
	case 'p': // validated domain name of the client IP
		value = validatedDomainName(ctx)
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
		value = spfURLEncode(value)
	}

	return value
}

// validateMacroString enforces RFC 7208 section 7's macro grammar before any
// DNS query is attempted. c, r and t are permitted only in exp= TXT content.
func validateMacroString(input string, allowExplanationOnly bool) error {
	for i := 0; i < len(input); {
		if input[i] != '%' {
			i++
			continue
		}
		if i+1 >= len(input) {
			return fmt.Errorf("trailing %%")
		}
		switch input[i+1] {
		case '%', '_', '-':
			i += 2
			continue
		case '{':
			endOffset := strings.IndexByte(input[i+2:], '}')
			if endOffset < 0 {
				return fmt.Errorf("unterminated macro")
			}
			macro := input[i+2 : i+2+endOffset]
			if err := validateSingleMacro(macro, allowExplanationOnly); err != nil {
				return err
			}
			i += endOffset + 3
		default:
			return fmt.Errorf("invalid escape %%%c", input[i+1])
		}
	}
	return nil
}

func validateSingleMacro(macro string, allowExplanationOnly bool) error {
	if macro == "" {
		return fmt.Errorf("empty macro")
	}
	letter := byte(strings.ToLower(string(macro[0]))[0])
	if !strings.ContainsRune("slodipvh", rune(letter)) &&
		!(allowExplanationOnly && strings.ContainsRune("crt", rune(letter))) {
		return fmt.Errorf("unsupported macro letter %q", macro[0])
	}
	rest := macro[1:]
	i := 0
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	if i > 0 {
		if _, err := strconv.ParseUint(rest[:i], 10, 31); err != nil {
			return fmt.Errorf("invalid transformer count in %%{%s}", macro)
		}
	}
	if i < len(rest) && (rest[i] == 'r' || rest[i] == 'R') {
		i++
	}
	for ; i < len(rest); i++ {
		if !strings.ContainsRune(".-+,/_=", rune(rest[i])) {
			return fmt.Errorf("invalid transformer in %%{%s}", macro)
		}
	}
	return nil
}

// validatedDomainName implements the %{p} macro using forward-confirmed
// reverse DNS. RFC 7208 limits validation to the first ten PTR names.
func validatedDomainName(ctx *spfContext) string {
	if ctx.validatedSet {
		return ctx.validatedName
	}
	ctx.validatedSet = true
	ctx.validatedName = "unknown"
	clientIP := net.ParseIP(ctx.senderIP)
	if clientIP == nil {
		return ctx.validatedName
	}
	names, err := lookupAddr(ctx.senderIP)
	if err != nil {
		return ctx.validatedName
	}
	if len(names) > 10 {
		names = names[:10]
	}
	var fallback string
	for _, rawName := range names {
		name := strings.TrimSuffix(strings.ToLower(rawName), ".")
		addresses, err := lookupHost(name)
		if err != nil {
			continue
		}
		confirmed := false
		for _, address := range addresses {
			if parsed := net.ParseIP(address); parsed != nil && parsed.Equal(clientIP) {
				confirmed = true
				break
			}
		}
		if !confirmed {
			continue
		}
		if fallback == "" {
			fallback = name
		}
		domain := strings.TrimSuffix(strings.ToLower(ctx.domain), ".")
		if name == domain || strings.HasSuffix(name, "."+domain) {
			ctx.validatedName = name
			return ctx.validatedName
		}
	}
	if fallback != "" {
		ctx.validatedName = fallback
	}
	return ctx.validatedName
}

func spfURLEncode(value string) string {
	const hex = "0123456789ABCDEF"
	var encoded strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || strings.ContainsRune("-._~", rune(c)) {
			encoded.WriteByte(c)
			continue
		}
		encoded.WriteByte('%')
		encoded.WriteByte(hex[c>>4])
		encoded.WriteByte(hex[c&0x0f])
	}
	return encoded.String()
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
func matchAWithCIDR(clientIP net.IP, domain string, cidr4, cidr6 int, ctx *spfContext, countTerm bool) (bool, string) {
	if countTerm && !consumeSPFLookup(ctx) {
		return false, "permerror"
	}
	addrs, err := lookupHost(domain)
	if err != nil {
		return false, classifySPFDNSError(err, ctx)
	}
	if len(addrs) == 0 {
		return false, recordSPFVoidLookup(ctx)
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
			return true, ""
		}
	}
	return false, ""
}

// matchMXWithCIDR checks if clientIP matches any MX host's A/AAAA records with CIDR.
// RFC 7208 §4.6.4: Limits MX records processed to 10.
func matchMXWithCIDR(clientIP net.IP, domain string, cidr4, cidr6 int, ctx *spfContext) (bool, string) {
	if !consumeSPFLookup(ctx) {
		return false, "permerror"
	}
	mxRecords, err := lookupMX(domain)
	if err != nil {
		return false, classifySPFDNSError(err, ctx)
	}
	if len(mxRecords) == 0 {
		return false, recordSPFVoidLookup(ctx)
	}
	if len(mxRecords) > 10 {
		return false, "permerror"
	}
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		matched, result := matchAWithCIDR(clientIP, host, cidr4, cidr6, ctx, false)
		if result != "" || matched {
			return matched, result
		}
	}
	return false, ""
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
func matchExists(queryDomain string, ctx *spfContext) (bool, string) {
	if !consumeSPFLookup(ctx) {
		return false, "permerror"
	}
	addrs, err := lookupHost(queryDomain)
	if err != nil {
		return false, classifySPFDNSError(err, ctx)
	}
	if len(addrs) == 0 {
		return false, recordSPFVoidLookup(ctx)
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
			return true, ""
		}
	}
	return false, ""
}

// matchPTR implements the ptr mechanism (deprecated but required for compatibility).
// RFC 7208 §5.5: Check if any PTR record for clientIP resolves to a name under checkDomain.
// Limits PTR records processed to 10 per RFC 7208 §4.6.4.
func matchPTR(clientIP net.IP, checkDomain string, ctx *spfContext) (bool, string) {
	if !consumeSPFLookup(ctx) {
		return false, "permerror"
	}

	// Get PTR records for the IP
	names, err := lookupAddr(clientIP.String())
	if err != nil {
		// RFC 7208 section 5.5 explicitly makes PTR DNS errors no-match.
		return false, ""
	}
	if len(names) == 0 {
		return false, recordSPFVoidLookup(ctx)
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
			addrs, err := lookupHost(name)
			if err != nil {
				// Forward-confirmation errors skip this name (RFC 7208 section 5.5).
				continue
			}
			for _, addr := range addrs {
				if net.ParseIP(addr).Equal(clientIP) {
					return true, ""
				}
			}
		}
	}
	return false, ""
}

func consumeSPFLookup(ctx *spfContext) bool {
	if ctx.lookups >= 10 {
		return false
	}
	ctx.lookups++
	return true
}

func recordSPFVoidLookup(ctx *spfContext) string {
	ctx.voidLookups++
	if ctx.voidLookups > 2 {
		return "permerror"
	}
	return ""
}

func classifySPFDNSError(err error, ctx *spfContext) string {
	if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
		return recordSPFVoidLookup(ctx)
	}
	return "temperror"
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
