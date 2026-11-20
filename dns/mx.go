package dns

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

var ErrNullMX = errors.New("556 5.1.10 recipient domain does not accept mail (null MX)")
var ErrNoMailRoute = errors.New("550 5.1.2 recipient domain has no MX or address records")

var errMalformedNullMX = errors.New("malformed null MX RRset")

var lookupMX = net.LookupMX
var lookupHost = net.LookupHost

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
		// Each delivery gets a new tie order without mutating the cache.
		records := append([]MXRecord(nil), cached.([]MXRecord)...)
		shuffleMXPreferences(records, rand.IntN)
		log.Printf("[dns] MX cache hit for %s: %d records", domain, len(records))
		for _, r := range records {
			log.Printf("[dns]   MX %s pref=%d", r.Host, r.Pref)
		}
		return records, nil
	}

	mxRecords, err := lookupMX(domain)
	if err != nil {
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
			return nil, fmt.Errorf("MX lookup for %s: %w", domain, err)
		}
	}
	if len(mxRecords) == 0 {
		log.Printf("[dns] MX lookup for %s returned err=%v, count=%d, falling back to A/AAAA", domain, err, len(mxRecords))
		// Fallback: try A/AAAA
		addrs, err2 := lookupHost(domain)
		if err2 != nil {
			var dnsErr *net.DNSError
			if errors.As(err2, &dnsErr) && dnsErr.IsNotFound {
				return nil, fmt.Errorf("%s: %w", domain, ErrNoMailRoute)
			}
			return nil, fmt.Errorf("MX address fallback for %s: %w", domain, err2)
		}
		if len(addrs) > 0 {
			log.Printf("[dns] using A/AAAA fallback for %s: %s", domain, addrs[0])
			records := []MXRecord{{Host: domain, Pref: 0}}
			globalCache.Set("mx:"+domain, records)
			return records, nil
		}
		return nil, fmt.Errorf("%s: %w", domain, ErrNoMailRoute)
	}
	records := make([]MXRecord, len(mxRecords))
	for i, mx := range mxRecords {
		host := mx.Host
		if host != "." {
			host = strings.TrimSuffix(host, ".")
		}
		records[i] = MXRecord{
			Host: host,
			Pref: mx.Pref,
		}
	}
	if err := checkNullMX(records); err != nil {
		return nil, err
	}

	// Sort by preference (lower = higher priority)
	sort.Slice(records, func(i, j int) bool {
		return records[i].Pref < records[j].Pref
	})

	log.Printf("[dns] MX lookup for %s: %d records", domain, len(records))
	for _, r := range records {
		log.Printf("[dns]   MX %s pref=%d", r.Host, r.Pref)
	}

	globalCache.Set("mx:"+domain, append([]MXRecord(nil), records...))
	shuffleMXPreferences(records, rand.IntN)
	return records, nil
}

// LookupMXAuthenticated resolves the complete MX/CNAME path through a trusted
// DNSSEC-validating resolver. Mandatory DANE must not use an insecure MX name.
func LookupMXAuthenticated(domain string) ([]MXRecord, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return nil, fmt.Errorf("empty MX domain")
	}
	dnsServersMu.RLock()
	servers := append([]string(nil), dnsServers...)
	dnsServersMu.RUnlock()
	var failures []error
	for _, server := range servers {
		records, err := queryAuthenticatedMX(domain, server)
		if err == nil || errors.Is(err, ErrNullMX) || errors.Is(err, ErrNoMailRoute) {
			return records, err
		}
		failures = append(failures, fmt.Errorf("%s: %w", server, err))
	}
	return nil, fmt.Errorf("authenticated MX lookup for %s: %w", domain, errors.Join(failures...))
}

func queryAuthenticatedMX(domain, server string) ([]MXRecord, error) {
	endpoint, tlsName, _ := strings.Cut(server, "#")
	client := &mdns.Client{Net: "udp", Timeout: 5 * time.Second}
	if tlsName != "" {
		client.Net = "tcp-tls"
		client.TLSConfig = &tls.Config{ServerName: tlsName, MinVersion: tls.VersionTLS12}
	}
	name := mdns.Fqdn(domain)
	seen := make(map[string]bool)
	for len(seen) < 8 {
		if seen[name] {
			return nil, fmt.Errorf("MX CNAME loop at %s", name)
		}
		seen[name] = true
		request := new(mdns.Msg)
		request.SetQuestion(name, mdns.TypeMX)
		request.SetEdns0(1232, true)
		response, _, err := client.Exchange(request, endpoint)
		if err != nil {
			return nil, fmt.Errorf("MX DNS query: %w", err)
		}
		if response.Truncated && client.Net == "udp" {
			client.Net = "tcp"
			response, _, err = client.Exchange(request, endpoint)
			if err != nil {
				return nil, fmt.Errorf("MX DNS TCP retry: %w", err)
			}
		}
		if !response.AuthenticatedData {
			return nil, ErrDNSSECInsecure
		}
		if response.Rcode == mdns.RcodeNameError {
			return nil, fmt.Errorf("%s: %w", domain, ErrNoMailRoute)
		}
		if response.Rcode != mdns.RcodeSuccess {
			return nil, fmt.Errorf("MX DNS response code: %s", mdns.RcodeToString[response.Rcode])
		}
		var records []MXRecord
		var alias string
		aliasCount := 0
		for _, answer := range response.Answer {
			switch rr := answer.(type) {
			case *mdns.MX:
				if strings.EqualFold(rr.Hdr.Name, name) {
					host := rr.Mx
					if host != "." {
						host = strings.TrimSuffix(host, ".")
					}
					records = append(records, MXRecord{Host: host, Pref: rr.Preference})
				}
			case *mdns.CNAME:
				if strings.EqualFold(rr.Hdr.Name, name) {
					alias = strings.ToLower(rr.Target)
					aliasCount++
				}
			}
		}
		if aliasCount > 1 || aliasCount > 0 && len(records) > 0 {
			return nil, fmt.Errorf("contradictory MX/CNAME answer for %s", name)
		}
		if alias != "" {
			name = alias
			continue
		}
		if err := checkNullMX(records); err != nil {
			return nil, err
		}
		if len(records) == 0 {
			if _, secure, err := querySecureMXAddressName(strings.TrimSuffix(name, "."), server); err != nil {
				if errors.Is(err, ErrNoMailRoute) {
					return nil, fmt.Errorf("%s: %w", domain, ErrNoMailRoute)
				}
				return nil, fmt.Errorf("authenticated MX address fallback for %s: %w", domain, err)
			} else if !secure {
				return nil, ErrDNSSECInsecure
			}
			return []MXRecord{{Host: strings.TrimSuffix(name, "."), Pref: 0}}, nil
		}
		sort.Slice(records, func(i, j int) bool { return records[i].Pref < records[j].Pref })
		shuffleMXPreferences(records, rand.IntN)
		return records, nil
	}
	return nil, fmt.Errorf("MX CNAME chain too long for %s", domain)
}

// A null MX is an unambiguous no-service declaration only when it is the
// sole MX record and has preference zero (RFC 7505). A contradictory RRset
// must not turn into a permanent non-delivery decision.
func checkNullMX(records []MXRecord) error {
	for _, record := range records {
		if record.Host == "." {
			if len(records) == 1 && record.Pref == 0 {
				return ErrNullMX
			}
			return errMalformedNullMX
		}
	}
	return nil
}

// shuffleMXPreferences spreads deliveries over equal-priority hosts while
// preserving strict MX preference ordering.
func shuffleMXPreferences(records []MXRecord, intN func(int) int) {
	for start := 0; start < len(records); {
		end := start + 1
		for end < len(records) && records[end].Pref == records[start].Pref {
			end++
		}
		for i := end - 1; i > start; i-- {
			j := start + intN(i-start+1)
			records[i], records[j] = records[j], records[i]
		}
		start = end
	}
}
