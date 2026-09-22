package dns

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

var (
	dnsServers   = []string{"1.1.1.1:853#cloudflare-dns.com", "8.8.8.8:853#dns.google"}
	dnsServersMu sync.RWMutex
)

func SetDNSServers(servers []string) {
	if len(servers) == 0 {
		return
	}
	dnsServersMu.Lock()
	dnsServers = append([]string(nil), servers...)
	dnsServersMu.Unlock()
}

type TLSARecord struct {
	Usage, Selector, MatchingType uint8
	CertData                      string
}

// TLSAResult preserves the security distinction between authenticated absence,
// insecure data and a lookup failure. DANE callers may only use authenticated data.
type TLSAResult struct {
	Records       []TLSARecord
	Authenticated bool
	Name          string
	TTL           time.Duration
}

var (
	ErrDNSSECInsecure = errors.New("TLSA response is not DNSSEC authenticated")
	ErrNoTLSA         = errors.New("authenticated denial of TLSA records")
)

func LookupTLSA(host string) (TLSAResult, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return TLSAResult{}, fmt.Errorf("empty TLSA host")
	}
	name := fmt.Sprintf("_25._tcp.%s.", host)
	cacheKey := "tlsa:v2:" + host
	if cached, ok := globalCache.Get(cacheKey); ok {
		return cached.(TLSAResult), nil
	}
	dnsServersMu.RLock()
	servers := append([]string(nil), dnsServers...)
	dnsServersMu.RUnlock()
	var errs []error
	for _, server := range servers {
		result, err := queryTLSARecords(name, server)
		if err == nil || errors.Is(err, ErrNoTLSA) {
			globalCache.SetWithTTL(cacheKey, result, result.TTL)
			return result, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", server, err))
	}
	return TLSAResult{Name: name}, errors.Join(errs...)
}

func queryTLSARecords(name, server string) (TLSAResult, error) {
	endpoint, tlsName, _ := strings.Cut(server, "#")
	msg := new(mdns.Msg)
	msg.SetQuestion(name, mdns.TypeTLSA)
	msg.SetEdns0(1232, true)
	client := &mdns.Client{Net: "udp", Timeout: 5 * time.Second}
	if tlsName != "" {
		client.Net = "tcp-tls"
		client.TLSConfig = &tls.Config{ServerName: tlsName, MinVersion: tls.VersionTLS12}
	}
	resp, _, err := client.Exchange(msg, endpoint)
	if err != nil {
		return TLSAResult{Name: name}, fmt.Errorf("DNS query: %w", err)
	}
	if resp.Truncated && client.Net == "udp" {
		client.Net = "tcp"
		resp, _, err = client.Exchange(msg, endpoint)
		if err != nil {
			return TLSAResult{Name: name}, fmt.Errorf("DNS TCP retry: %w", err)
		}
	}
	result := TLSAResult{Name: name, Authenticated: resp.AuthenticatedData, TTL: time.Minute}
	if !resp.AuthenticatedData {
		return result, ErrDNSSECInsecure
	}
	if resp.Rcode == mdns.RcodeNameError {
		return result, ErrNoTLSA
	}
	if resp.Rcode != mdns.RcodeSuccess {
		return result, fmt.Errorf("DNS response code: %s", mdns.RcodeToString[resp.Rcode])
	}
	minTTL := uint32(300)
	for _, answer := range resp.Answer {
		rr, ok := answer.(*mdns.TLSA)
		if !ok {
			continue
		}
		record, parseErr := validateTLSA(TLSARecord{rr.Usage, rr.Selector, rr.MatchingType, rr.Certificate})
		if parseErr != nil {
			log.Printf("[dns] ignoring malformed TLSA record for %s: %v", name, parseErr)
			continue
		}
		if rr.Hdr.Ttl < minTTL {
			minTTL = rr.Hdr.Ttl
		}
		result.Records = append(result.Records, record)
	}
	result.TTL = time.Duration(minTTL) * time.Second
	if result.TTL <= 0 || result.TTL > time.Hour {
		result.TTL = 5 * time.Minute
	}
	if len(result.Records) == 0 {
		return result, ErrNoTLSA
	}
	return result, nil
}

func validateTLSA(record TLSARecord) (TLSARecord, error) {
	if record.Usage > 3 {
		return TLSARecord{}, fmt.Errorf("unsupported certificate usage %d", record.Usage)
	}
	if record.Selector > 1 {
		return TLSARecord{}, fmt.Errorf("unsupported selector %d", record.Selector)
	}
	if record.MatchingType > 2 {
		return TLSARecord{}, fmt.Errorf("unsupported matching type %d", record.MatchingType)
	}
	record.CertData = strings.ToLower(strings.TrimSpace(record.CertData))
	b, err := hex.DecodeString(record.CertData)
	if err != nil {
		return TLSARecord{}, fmt.Errorf("association data is not hex: %w", err)
	}
	if len(b) == 0 {
		return TLSARecord{}, fmt.Errorf("empty association data")
	}
	expected := 0
	if record.MatchingType == 1 {
		expected = 32
	}
	if record.MatchingType == 2 {
		expected = 64
	}
	if expected != 0 && len(b) != expected {
		return TLSARecord{}, fmt.Errorf("matching type %d requires %d bytes, got %d", record.MatchingType, expected, len(b))
	}
	return record, nil
}

func ParseTLSARecord(data string) (TLSARecord, error) {
	parts := strings.Fields(data)
	if len(parts) < 4 {
		return TLSARecord{}, fmt.Errorf("invalid TLSA record format")
	}
	values := make([]uint64, 3)
	for i := range values {
		v, err := strconv.ParseUint(parts[i], 10, 8)
		if err != nil {
			return TLSARecord{}, fmt.Errorf("invalid TLSA field %d: %w", i+1, err)
		}
		values[i] = v
	}
	return validateTLSA(TLSARecord{uint8(values[0]), uint8(values[1]), uint8(values[2]), strings.Join(parts[3:], "")})
}
