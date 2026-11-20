package mta_sts

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"gomail/logging"
	"gomail/store"
)

// cachedPolicy holds a policy and when it expires
type cachedPolicy struct {
	policy    *Policy
	policyID  string // From DNS TXT record
	expiresAt time.Time
}

type failedPolicyFetch struct {
	policyID string
	retryAt  time.Time
}

var (
	policyCache   = make(map[string]*cachedPolicy)
	failedFetches = make(map[string]failedPolicyFetch)
	cacheMutex    sync.RWMutex
	persistLocks  [64]sync.Mutex
	httpClient    = &http.Client{
		Timeout: 10 * time.Second,
		// RFC 8461 policy retrieval is bound to the fixed HTTPS policy host.
		// A redirect must not move the policy to another host or scheme.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	lookupTXT      = net.LookupTXT
	policyDocument = fetchPolicyDocument
)

// FetchPolicyWithStore uses the durable cache for outbound delivery. A store
// failure is returned rather than silently dropping an enforce policy.
func FetchPolicyWithStore(domain string, db *store.DB) (*Policy, error) {
	if db == nil {
		return FetchPolicy(domain), nil
	}
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(domain))
	lock := &persistLocks[hash.Sum32()%uint32(len(persistLocks))]
	lock.Lock()
	defer lock.Unlock()
	id, document, expiry, err := db.LoadMTASTSPolicy(domain)
	if err != nil {
		return nil, fmt.Errorf("loading MTA-STS policy cache: %w", err)
	}
	if id != "" && time.Now().Before(expiry) {
		var policy Policy
		if err := json.Unmarshal([]byte(document), &policy); err != nil {
			logging.Warn(fmt.Sprintf("[mta-sts] ignoring invalid cached policy for %s: %v", domain, err))
		} else if err := policy.validate(); err != nil {
			logging.Warn(fmt.Sprintf("[mta-sts] ignoring invalid cached policy for %s: %v", domain, err))
		} else if expiry.After(time.Now().Add(time.Duration(policy.MaxAge) * time.Second)) {
			logging.Warn(fmt.Sprintf("[mta-sts] ignoring cached policy for %s with expiry beyond max_age", domain))
		} else {
			cacheMutex.Lock()
			cached := policyCache[domain]
			if cached == nil || cached.expiresAt.Before(expiry) {
				policyCache[domain] = &cachedPolicy{policy: &policy, policyID: id, expiresAt: expiry}
			}
			cacheMutex.Unlock()
		}
	}
	policy := FetchPolicy(domain)
	cacheMutex.RLock()
	cached := policyCache[domain]
	cacheMutex.RUnlock()
	if cached != nil && time.Now().Before(cached.expiresAt) && (id != cached.policyID || !expiry.Equal(cached.expiresAt)) {
		encoded, err := json.Marshal(cached.policy)
		if err != nil {
			return nil, err
		}
		if err := db.SaveMTASTSPolicy(domain, cached.policyID, string(encoded), cached.expiresAt); err != nil {
			return nil, fmt.Errorf("saving MTA-STS policy cache: %w", err)
		}
	}
	return policy, nil
}

// fetchDNSTXTRecord fetches the MTA-STS DNS TXT record for a domain.
// Returns the policy ID if found, empty string otherwise.
// Format: _mta-sts.<domain> TXT v=STSv1; id=<id>
func fetchDNSTXTRecord(domain string) string {
	// Query DNS for _mta-sts.<domain> TXT record
	txtDomain := "_mta-sts." + domain
	records, err := lookupTXT(txtDomain)
	if err != nil {
		logging.Info(fmt.Sprintf("[mta-sts] DNS TXT lookup for %s failed: %v", txtDomain, err))
		return ""
	}

	// RFC 8461 requires exactly one version-matching TXT record. An invalid
	// matching record cannot be hidden by another valid one in the RRset.
	var matching []string
	for _, record := range records {
		if stsVersionWithWhitespaceDelimiter(record) {
			matching = append(matching, record)
		}
	}
	if len(matching) == 1 {
		if id, ok := parseSTSTXTRecord(matching[0]); ok {
			logging.Info(fmt.Sprintf("[mta-sts] DNS TXT record found for %s: id=%s", domain, id))
			return id
		}
	}

	logging.Info(fmt.Sprintf("[mta-sts] no valid MTA-STS DNS TXT record for %s", domain))
	return ""
}

func stsVersionWithWhitespaceDelimiter(record string) bool {
	if !strings.HasPrefix(record, "v=STSv1") {
		return false
	}
	return strings.HasPrefix(strings.TrimLeft(record[len("v=STSv1"):], " \t"), ";")
}

func parseSTSTXTRecord(record string) (string, bool) {
	fields := strings.Split(record, ";")
	if len(fields) < 2 || strings.TrimRight(fields[0], " \t") != "v=STSv1" {
		return "", false
	}
	var id string
	for i, field := range fields[1:] {
		field = strings.Trim(field, " \t")
		if field == "" && i == len(fields)-2 { // optional trailing delimiter
			continue
		}
		key, value, ok := strings.Cut(field, "=")
		if !ok || !validSTSFieldName(key) || !validSTSExtensionValue(value) {
			return "", false
		}
		if key == "id" {
			if len(value) == 0 || len(value) > 32 {
				return "", false
			}
			for i := 0; i < len(value); i++ {
				if !asciiAlphanumeric(value[i]) {
					return "", false
				}
			}
			if id == "" { // RFC 8461: first non-repeated field wins.
				id = value
			}
		}
	}
	return id, id != ""
}

func validSTSFieldName(name string) bool {
	if len(name) == 0 || len(name) > 32 || !asciiAlphanumeric(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if !asciiAlphanumeric(c) && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func validSTSExtensionValue(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < '!' || c > '~' || c == ';' || c == '=' {
			return false
		}
	}
	return true
}

func asciiAlphanumeric(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

// FetchPolicy fetches an MTA-STS policy for a domain.
// It checks the DNS TXT record first (_mta-sts.<domain>), then fetches from HTTPS.
// Caches the policy respecting the policy's max_age.
// If no policy is found or fails to fetch, returns nil (policy optional).
// RFC 8461 compliant.
func FetchPolicy(domain string) *Policy {
	// Step 1: Check DNS TXT record to get policy ID
	dnsID := fetchDNSTXTRecord(domain)

	// Step 2: Check cache. Keep a valid prior policy available while a newly
	// announced policy ID is fetched; a transient HTTPS failure must not
	// downgrade an enforce policy to opportunistic delivery.
	var validCached *cachedPolicy
	cacheMutex.RLock()
	if cached, ok := policyCache[domain]; ok {
		// Cache hit: check if still valid
		if time.Now().Before(cached.expiresAt) {
			validCached = cached
			// Check if policy ID changed
			if dnsID == "" || dnsID == cached.policyID {
				// Policy unchanged, return cached
				cacheMutex.RUnlock()
				logging.Info(fmt.Sprintf("[mta-sts] using cached policy for %s (id=%s)", domain, cached.policyID))
				return cached.policy
			}
			// Policy ID changed, need to refetch
			logging.Info(fmt.Sprintf("[mta-sts] policy ID changed for %s (old=%s, new=%s), refetching", domain, cached.policyID, dnsID))
		}
	}
	cacheMutex.RUnlock()
	// A policy is discoverable only through a valid _mta-sts TXT record.
	if dnsID == "" {
		return nil
	}
	cacheMutex.RLock()
	failed, recentlyFailed := failedFetches[domain]
	cacheMutex.RUnlock()
	if recentlyFailed && failed.policyID == dnsID && time.Now().Before(failed.retryAt) {
		if validCached != nil {
			return validCached.policy
		}
		return nil
	}

	// Step 3: Fetch HTTPS policy (cache miss or ID changed)
	policy, err := policyDocument(domain)
	if err != nil {
		cacheMutex.Lock()
		failedFetches[domain] = failedPolicyFetch{policyID: dnsID, retryAt: time.Now().Add(5 * time.Minute)}
		cacheMutex.Unlock()
		logging.Info(fmt.Sprintf("[mta-sts] failed to fetch replacement policy for %s: %v", domain, err))
		if validCached != nil {
			logging.Warn(fmt.Sprintf("[mta-sts] retaining still-valid cached policy for %s after replacement fetch failure", domain))
			return validCached.policy
		}
		return nil
	}

	// Step 4: Cache policy respecting max_age
	cacheMutex.Lock()
	delete(failedFetches, domain)
	policyCache[domain] = &cachedPolicy{
		policy:    policy,
		policyID:  dnsID,
		expiresAt: time.Now().Add(time.Duration(policy.MaxAge) * time.Second),
	}
	cacheMutex.Unlock()

	logging.Info(fmt.Sprintf("[mta-sts] fetched policy for %s (mode=%s, id=%s, max_age=%d)", domain, policy.Mode, dnsID, policy.MaxAge))
	return policy
}

func fetchPolicyDocument(domain string) (*Policy, error) {
	url := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Add User-Agent header (some servers require this)
	req.Header.Set("User-Agent", "GoMail/1.0 (+https://github.com/yourusername/gomail)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("policy endpoint returned HTTP %d", resp.StatusCode)
	}
	if resp.Request == nil || resp.Request.URL.String() != url {
		return nil, fmt.Errorf("policy endpoint changed URL")
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "text/plain") {
		return nil, fmt.Errorf("policy endpoint must return text/plain")
	}

	// Read response body (limit to 64KB to prevent abuse)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 64*1024 {
		return nil, fmt.Errorf("policy body exceeds 64 KiB limit")
	}

	// Parse policy
	policy, err := ParsePolicy(string(body))
	if err != nil {
		return nil, err
	}
	return policy, nil
}

// ClearPolicyCache clears the policy cache (useful for testing)
func ClearPolicyCache() {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	policyCache = make(map[string]*cachedPolicy)
	failedFetches = make(map[string]failedPolicyFetch)
}
