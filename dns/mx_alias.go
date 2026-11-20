package dns

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

// LookupTLSAForMX tries the securely expanded MX address name before the
// original MX hostname, as required by RFC 7672. A signed but unusable RRset
// is a TLS commitment and therefore stops the candidate search.
func LookupTLSAForMX(host string) (TLSAResult, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return TLSAResult{}, fmt.Errorf("empty MX hostname")
	}
	dnsServersMu.RLock()
	servers := append([]string(nil), dnsServers...)
	dnsServersMu.RUnlock()
	var expanded string
	var lookupErr error
	for _, server := range servers {
		var secure bool
		expanded, secure, lookupErr = querySecureMXAddressName(host, server)
		if lookupErr == nil {
			if !secure {
				expanded = ""
			}
			break
		}
	}
	if lookupErr != nil {
		return TLSAResult{}, fmt.Errorf("MX address alias lookup for %s: %w", host, lookupErr)
	}
	if expanded != "" && expanded != host {
		result, err := LookupTLSA(expanded)
		if err == nil && (len(result.Records) > 0 || result.UnusableRecords) {
			return result, nil
		}
		if err != nil && !errors.Is(err, ErrDNSSECInsecure) && !errors.Is(err, ErrNoTLSA) {
			return result, err
		}
	}
	return LookupTLSA(host)
}

// querySecureMXAddressName accepts a canonical name only when each CNAME hop
// and the terminal A or AAAA RRset were authenticated by the DNSSEC resolver.
func querySecureMXAddressName(host, server string) (string, bool, error) {
	endpoint, tlsName, _ := strings.Cut(server, "#")
	client := &mdns.Client{Net: "udp", Timeout: 5 * time.Second}
	if tlsName != "" {
		client.Net = "tcp-tls"
		client.TLSConfig = &tls.Config{ServerName: tlsName, MinVersion: tls.VersionTLS12}
	}
	current := mdns.Fqdn(host)
	seen := make(map[string]bool)
	for len(seen) < 8 {
		if seen[strings.ToLower(current)] {
			return "", false, fmt.Errorf("MX address CNAME loop at %s", current)
		}
		seen[strings.ToLower(current)] = true
		var next string
		for _, qtype := range []uint16{mdns.TypeA, mdns.TypeAAAA} {
			request := new(mdns.Msg)
			request.SetQuestion(current, qtype)
			request.SetEdns0(1232, true)
			response, _, err := client.Exchange(request, endpoint)
			if err != nil {
				return "", false, err
			}
			if response.Truncated && client.Net == "udp" {
				client.Net = "tcp"
				response, _, err = client.Exchange(request, endpoint)
				if err != nil {
					return "", false, err
				}
			}
			if response.Rcode == mdns.RcodeNameError && response.AuthenticatedData {
				return "", false, ErrNoMailRoute
			}
			if response.Rcode != mdns.RcodeSuccess {
				return "", false, fmt.Errorf("MX address DNS response code: %s", mdns.RcodeToString[response.Rcode])
			}
			if !response.AuthenticatedData {
				return host, false, nil
			}
			aliasCount := 0
			addressAtCurrent := false
			for _, answer := range response.Answer {
				switch rr := answer.(type) {
				case *mdns.CNAME:
					if strings.EqualFold(rr.Hdr.Name, current) {
						next = rr.Target
						aliasCount++
					}
				case *mdns.A:
					addressAtCurrent = addressAtCurrent || strings.EqualFold(rr.Hdr.Name, current)
				case *mdns.AAAA:
					addressAtCurrent = addressAtCurrent || strings.EqualFold(rr.Hdr.Name, current)
				}
			}
			if aliasCount > 1 || aliasCount > 0 && addressAtCurrent {
				return "", false, fmt.Errorf("contradictory MX address CNAME answer for %s", current)
			}
			if next != "" {
				break
			}
			for _, answer := range response.Answer {
				switch rr := answer.(type) {
				case *mdns.A:
					if qtype == mdns.TypeA && strings.EqualFold(rr.Hdr.Name, current) {
						return strings.TrimSuffix(strings.ToLower(current), "."), true, nil
					}
				case *mdns.AAAA:
					if qtype == mdns.TypeAAAA && strings.EqualFold(rr.Hdr.Name, current) {
						return strings.TrimSuffix(strings.ToLower(current), "."), true, nil
					}
				}
			}
		}
		if next == "" {
			return "", false, ErrNoMailRoute
		}
		current = mdns.Fqdn(next)
	}
	return "", false, fmt.Errorf("MX address CNAME chain too long for %s", host)
}
