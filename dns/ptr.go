package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const ptrLookupTimeout = 5 * time.Second

type ptrLookupResolver interface {
	LookupAddr(context.Context, string) ([]string, error)
	LookupHost(context.Context, string) ([]string, error)
}

// VerifyPTR checks that the connecting IP has a valid reverse DNS record
// that resolves back to the same IP (forward-confirmed reverse DNS).
func VerifyPTR(ip string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ptrLookupTimeout)
	defer cancel()
	return verifyPTR(ctx, net.DefaultResolver, ip)
}

func verifyPTR(ctx context.Context, resolver ptrLookupResolver, ip string) (string, bool, error) {
	// Check cache
	cacheKey := "ptr:" + ip
	if cached, ok := globalCache.Get(cacheKey); ok {
		result := cached.(*ptrResult)
		return result.hostname, result.valid, nil
	}

	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		if err == nil {
			err = fmt.Errorf("no PTR records")
			globalCache.Set(cacheKey, &ptrResult{"", false})
		}
		return "", false, fmt.Errorf("PTR lookup for %s: %w", ip, err)
	}

	hostname := strings.TrimSuffix(names[0], ".")

	// Forward-confirm: hostname should resolve back to the same IP
	addrs, err := resolver.LookupHost(ctx, hostname)
	if err != nil {
		return hostname, false, fmt.Errorf("forward lookup for %s: %w", hostname, err)
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
