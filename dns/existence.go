package dns

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

// DomainExists distinguishes NXDOMAIN from an existing name with no MX RRset.
// DMARC np= policy applies only to the former (RFC 9989).
func DomainExists(domain string) (bool, error) {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return false, fmt.Errorf("empty DNS name")
	}
	dnsServersMu.RLock()
	servers := append([]string(nil), dnsServers...)
	dnsServersMu.RUnlock()
	var failures []error
	for _, server := range servers {
		exists, err := queryDomainExists(domain, server)
		if err == nil {
			return exists, nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", server, err))
	}
	return false, &net.DNSError{Err: errors.Join(failures...).Error(), Name: domain, IsTemporary: true}
}

func queryDomainExists(domain, server string) (bool, error) {
	endpoint, tlsName, _ := strings.Cut(server, "#")
	client := &mdns.Client{Net: "udp", Timeout: 5 * time.Second}
	if tlsName != "" {
		client.Net = "tcp-tls"
		client.TLSConfig = &tls.Config{ServerName: tlsName, MinVersion: tls.VersionTLS12}
	}
	request := new(mdns.Msg)
	request.SetQuestion(mdns.Fqdn(domain), mdns.TypeMX)
	response, _, err := client.Exchange(request, endpoint)
	if err != nil {
		return false, err
	}
	if response.Truncated && client.Net == "udp" {
		client.Net = "tcp"
		response, _, err = client.Exchange(request, endpoint)
		if err != nil {
			return false, err
		}
	}
	switch response.Rcode {
	case mdns.RcodeSuccess:
		return true, nil // NOERROR/NODATA still means the name exists.
	case mdns.RcodeNameError:
		return false, nil
	default:
		return false, fmt.Errorf("DNS response code: %s", mdns.RcodeToString[response.Rcode])
	}
}
