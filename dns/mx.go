package dns

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// MXRecord represents a mail exchange record.
type MXRecord struct {
	Host string
	Pref uint16
}

// LookupMX returns MX records for a domain, sorted by preference.
// Falls back to A/AAAA record if no MX records exist (RFC 5321 §5).
func LookupMX(domain string) ([]MXRecord, error) {
	domain = strings.TrimSuffix(domain, ".")

	// Check cache first
	if cached, ok := globalCache.Get("mx:" + domain); ok {
		return cached.([]MXRecord), nil
	}

	mxRecords, err := net.LookupMX(domain)
	if err != nil || len(mxRecords) == 0 {
		// Fallback: try A/AAAA
		addrs, err2 := net.LookupHost(domain)
		if err2 != nil {
			if err != nil {
				return nil, fmt.Errorf("MX lookup for %s: %w", domain, err)
			}
			return nil, fmt.Errorf("MX+A lookup for %s: %w", domain, err2)
		}
		if len(addrs) > 0 {
			records := []MXRecord{{Host: domain, Pref: 0}}
			globalCache.Set("mx:"+domain, records)
			return records, nil
		}
		return nil, fmt.Errorf("no MX or A records for %s", domain)
	}

	records := make([]MXRecord, len(mxRecords))
	for i, mx := range mxRecords {
		records[i] = MXRecord{
			Host: strings.TrimSuffix(mx.Host, "."),
			Pref: mx.Pref,
		}
	}

	// Sort by preference (lower = higher priority)
	sort.Slice(records, func(i, j int) bool {
		return records[i].Pref < records[j].Pref
	})

	globalCache.Set("mx:"+domain, records)
	return records, nil
}
