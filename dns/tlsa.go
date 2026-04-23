package dns

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// dnsServers are the DNS servers used for TLSA lookups
// Default: Google Public DNS and Cloudflare
var dnsServers = []string{"8.8.8.8:53", "1.1.1.1:53"}

// SetDNSServers allows customizing the DNS resolvers used for TLSA lookups
func SetDNSServers(servers []string) {
	if len(servers) > 0 {
		dnsServers = servers
	}
}

// TLSARecord represents a TLSA record for DANE (DNSSEC-based Authentication of Named Entities).
type TLSARecord struct {
	Usage        uint8  // 0=PKIX-TA, 1=PKIX-EE, 2=DANE-TA, 3=DANE-EE
	Selector     uint8  // 0=Full cert, 1=Public key
	MatchingType uint8  // 0=Exact, 1=SHA-256, 2=SHA-512
	CertData     string // Hex-encoded certificate or public key hash
}

// LookupTLSA returns TLSA records for an SMTP server (port 25).
// Per RFC 6698, the DNS name is _port._proto.host (e.g., _25._tcp.example.com)
// Uses miekg/dns library for actual DNS queries.
func LookupTLSA(host string) ([]TLSARecord, error) {
	host = strings.TrimSuffix(host, ".")

	// Check cache first
	cacheKey := "tlsa:" + host
	if cached, ok := globalCache.Get(cacheKey); ok {
		records := cached.([]TLSARecord)
		log.Printf("[dns] TLSA cache hit for %s: %d records", host, len(records))
		return records, nil
	}

	// Query TLSA records: _25._tcp.host (RFC 6698)
	tlsaName := fmt.Sprintf("_25._tcp.%s.", host)
	log.Printf("[dns] querying TLSA records for %s", tlsaName)

	// Try each DNS server
	var lastErr error
	for _, server := range dnsServers {
		records, err := queryTLSARecords(tlsaName, server)
		if err == nil {
			// Cache successful result (5 minutes TTL)
			globalCache.SetWithTTL(cacheKey, records, 5*time.Minute)
			log.Printf("[dns] TLSA lookup for %s: found %d records", host, len(records))
			return records, nil
		}
		lastErr = err
		log.Printf("[dns] TLSA query failed on %s: %v", server, err)
	}

	// No TLSA records found
	log.Printf("[dns] no TLSA records found for %s (fallback to standard TLS): %v", host, lastErr)
	globalCache.SetWithTTL(cacheKey, []TLSARecord{}, 1*time.Minute) // Cache miss for 1 min
	return []TLSARecord{}, nil
}

// queryTLSARecords performs actual DNS query for TLSA records using miekg/dns
func queryTLSARecords(tlsaName string, server string) ([]TLSARecord, error) {
	// Create DNS client with timeout
	client := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}

	// Build DNS query
	msg := &dns.Msg{}
	msg.SetQuestion(tlsaName, dns.TypeTLSA)
	msg.RecursionDesired = true

	// Query DNS server
	resp, _, err := client.Exchange(msg, server)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}

	// Check response code
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS response code: %s", dns.RcodeToString[resp.Rcode])
	}

	// Parse TLSA records from answer section
	var records []TLSARecord
	for _, ans := range resp.Answer {
		if tlsaRR, ok := ans.(*dns.TLSA); ok {
			record := TLSARecord{
				Usage:        tlsaRR.Usage,
				Selector:     tlsaRR.Selector,
				MatchingType: tlsaRR.MatchingType,
				CertData:     tlsaRR.Certificate, // Already hex-encoded string from miekg/dns
			}
			records = append(records, record)
			log.Printf("[dns] parsed TLSA: usage=%d selector=%d matchingType=%d certDataLen=%d",
				record.Usage, record.Selector, record.MatchingType, len(record.CertData))
		}
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no TLSA records in response")
	}

	return records, nil
}

// ParseTLSARecord parses a TLSA record string.
// Format: Usage Selector MatchingType CertData (space-separated hex digits)
func ParseTLSARecord(recordData string) (TLSARecord, error) {
	parts := strings.Fields(recordData)
	if len(parts) < 4 {
		return TLSARecord{}, fmt.Errorf("invalid TLSA record format: %s", recordData)
	}

	usage, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil {
		return TLSARecord{}, fmt.Errorf("invalid TLSA usage: %v", err)
	}

	selector, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return TLSARecord{}, fmt.Errorf("invalid TLSA selector: %v", err)
	}

	matchingType, err := strconv.ParseUint(parts[2], 10, 8)
	if err != nil {
		return TLSARecord{}, fmt.Errorf("invalid TLSA matching type: %v", err)
	}

	// Combine remaining parts as cert data (remove spaces)
	certData := strings.Join(parts[3:], "")

	return TLSARecord{
		Usage:        uint8(usage),
		Selector:     uint8(selector),
		MatchingType: uint8(matchingType),
		CertData:     certData,
	}, nil
}
