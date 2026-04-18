package mta_sts

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// cachedPolicy holds a policy and when it expires
type cachedPolicy struct {
	policy    *Policy
	policyID  string // From DNS TXT record
	expiresAt time.Time
}

var (
	policyCache = make(map[string]*cachedPolicy)
	cacheMutex  sync.RWMutex
	httpClient  = &http.Client{
		Timeout: 10 * time.Second,
	}
)

// fetchDNSTXTRecord fetches the MTA-STS DNS TXT record for a domain.
// Returns the policy ID if found, empty string otherwise.
// Format: _mta-sts.<domain> TXT v=STSv1; id=<id>
func fetchDNSTXTRecord(domain string) string {
	// Query DNS for _mta-sts.<domain> TXT record
	txtDomain := "_mta-sts." + domain
	records, err := net.LookupTXT(txtDomain)
	if err != nil {
		log.Printf("[mta-sts] DNS TXT lookup for %s failed: %v", txtDomain, err)
		return ""
	}

	// Parse TXT records for MTA-STS format
	for _, record := range records {
		// Expected format: v=STSv1; id=<id>
		if strings.HasPrefix(record, "v=STSv1") {
			// Parse id= value
			parts := strings.Split(record, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "id=") {
					id := strings.TrimPrefix(part, "id=")
					log.Printf("[mta-sts] DNS TXT record found for %s: id=%s", domain, id)
					return id
				}
			}
		}
	}

	log.Printf("[mta-sts] no valid MTA-STS DNS TXT record for %s", domain)
	return ""
}

// FetchPolicy fetches an MTA-STS policy for a domain.
// It checks the DNS TXT record first (_mta-sts.<domain>), then fetches from HTTPS.
// Caches the policy respecting the policy's max_age.
// If no policy is found or fails to fetch, returns nil (policy optional).
// RFC 8461 compliant.
func FetchPolicy(domain string) *Policy {
	// Step 1: Check DNS TXT record to get policy ID
	dnsID := fetchDNSTXTRecord(domain)

	// Step 2: Check cache
	cacheMutex.RLock()
	if cached, ok := policyCache[domain]; ok {
		// Cache hit: check if still valid
		if time.Now().Before(cached.expiresAt) {
			// Check if policy ID changed
			if dnsID == "" || dnsID == cached.policyID {
				// Policy unchanged, return cached
				cacheMutex.RUnlock()
				log.Printf("[mta-sts] using cached policy for %s (id=%s)", domain, cached.policyID)
				return cached.policy
			}
			// Policy ID changed, need to refetch
			log.Printf("[mta-sts] policy ID changed for %s (old=%s, new=%s), refetching", domain, cached.policyID, dnsID)
		}
	}
	cacheMutex.RUnlock()

	// Step 3: Fetch HTTPS policy (cache miss or ID changed)
	url := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("[mta-sts] failed to create request for %s: %v", domain, err)
		return nil
	}

	// Add User-Agent header (some servers require this)
	req.Header.Set("User-Agent", "GoMail/1.0 (+https://github.com/yourusername/gomail)")

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("[mta-sts] failed to fetch policy for %s: %v", domain, err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[mta-sts] non-200 response for %s: %d (URL: %s)", domain, resp.StatusCode, url)
		return nil
	}

	// Read response body (limit to 64KB to prevent abuse)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		log.Printf("[mta-sts] failed to read policy body for %s: %v", domain, err)
		return nil
	}

	// Parse policy
	policy, err := ParsePolicy(string(body))
	if err != nil {
		log.Printf("[mta-sts] failed to parse policy for %s: %v", domain, err)
		return nil
	}

	// Step 4: Cache policy respecting max_age
	cacheMutex.Lock()
	policyCache[domain] = &cachedPolicy{
		policy:    policy,
		policyID:  dnsID,
		expiresAt: time.Now().Add(time.Duration(policy.MaxAge) * time.Second),
	}
	cacheMutex.Unlock()

	log.Printf("[mta-sts] fetched policy for %s (mode=%s, id=%s, max_age=%d)", domain, policy.Mode, dnsID, policy.MaxAge)
	return policy
}

// ClearPolicyCache clears the policy cache (useful for testing)
func ClearPolicyCache() {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	policyCache = make(map[string]*cachedPolicy)
}
