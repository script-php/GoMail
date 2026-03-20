package dns

import (
	"fmt"
	"net"
	"strings"
)

// VerifyPTR checks that the connecting IP has a valid reverse DNS record
// that resolves back to the same IP (forward-confirmed reverse DNS).
func VerifyPTR(ip string) (string, bool, error) {
	// Check cache
	cacheKey := "ptr:" + ip
	if cached, ok := globalCache.Get(cacheKey); ok {
		result := cached.(*ptrResult)
		return result.hostname, result.valid, nil
	}

	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		result := &ptrResult{"", false}
		globalCache.Set(cacheKey, result)
		return "", false, fmt.Errorf("PTR lookup for %s: %w", ip, err)
	}

	hostname := strings.TrimSuffix(names[0], ".")

	// Forward-confirm: hostname should resolve back to the same IP
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		result := &ptrResult{hostname, false}
		globalCache.Set(cacheKey, result)
		return hostname, false, nil
	}

	for _, addr := range addrs {
		if addr == ip {
			result := &ptrResult{hostname, true}
			globalCache.Set(cacheKey, result)
			return hostname, true, nil
		}
	}

	result := &ptrResult{hostname, false}
	globalCache.Set(cacheKey, result)
	return hostname, false, nil
}

type ptrResult struct {
	hostname string
	valid    bool
}
