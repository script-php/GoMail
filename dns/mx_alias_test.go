package dns

import (
	"net"
	"strconv"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestLookupTLSAForMXAddressAliasCandidates(t *testing.T) {
	InitCache(60)
	valid := strings.Repeat("ab", 32)
	for index, tc := range []struct {
		name, canonicalAnswer string
		addressSecure         bool
		wantCanonical         bool
		wantUnusable          bool
	}{
		{"expanded name takes precedence", "TLSA", true, true, false},
		{"expanded name absent falls back", "ABSENT", true, false, false},
		{"insecure expanded TLSA falls back", "INSECURE", true, false, false},
		{"insecure address alias uses original", "TLSA", false, false, false},
		{"unusable expanded RRset still commits to TLS", "MALFORMED", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := "mx" + strconv.Itoa(index) + ".example.test"
			canonical := "canonical" + strconv.Itoa(index) + ".example.test"
			originalTLSA := "_25._tcp." + host + "."
			canonicalTLSA := "_25._tcp." + canonical + "."
			packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := &mdns.Server{PacketConn: packetConn, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
				response := new(mdns.Msg)
				response.SetReply(request)
				q := request.Question[0]
				response.AuthenticatedData = true
				var rr mdns.RR
				switch {
				case q.Qtype == mdns.TypeA && q.Name == host+".":
					response.AuthenticatedData = tc.addressSecure
					rr, _ = mdns.NewRR(host + ". 60 IN CNAME " + canonical + ".")
				case q.Qtype == mdns.TypeA && q.Name == canonical+".":
					rr, _ = mdns.NewRR(canonical + ". 60 IN A 192.0.2.1")
				case q.Qtype == mdns.TypeTLSA && q.Name == canonicalTLSA && tc.canonicalAnswer == "TLSA":
					rr, _ = mdns.NewRR(q.Name + " 60 IN TLSA 3 1 1 " + valid)
				case q.Qtype == mdns.TypeTLSA && q.Name == canonicalTLSA && tc.canonicalAnswer == "MALFORMED":
					rr, _ = mdns.NewRR(q.Name + " 60 IN TLSA 3 1 1 ab")
				case q.Qtype == mdns.TypeTLSA && q.Name == canonicalTLSA && tc.canonicalAnswer == "INSECURE":
					response.AuthenticatedData = false
				case q.Qtype == mdns.TypeTLSA && q.Name == originalTLSA:
					rr, _ = mdns.NewRR(q.Name + " 60 IN TLSA 3 1 1 " + strings.Repeat("cd", 32))
				}
				if rr != nil {
					response.Answer = []mdns.RR{rr}
				}
				_ = w.WriteMsg(response)
			})}
			go func() { _ = server.ActivateAndServe() }()
			defer server.Shutdown()
			dnsServersMu.RLock()
			oldServers := append([]string(nil), dnsServers...)
			dnsServersMu.RUnlock()
			SetDNSServers([]string{packetConn.LocalAddr().String()})
			defer SetDNSServers(oldServers)
			result, err := LookupTLSAForMX(host)
			if err != nil {
				t.Fatal(err)
			}
			wantName := originalTLSA
			if tc.wantCanonical {
				wantName = canonicalTLSA
			}
			wantRecords := 1
			if tc.wantUnusable {
				wantRecords = 0
			}
			if result.Name != wantName || len(result.Records) != wantRecords || result.UnusableRecords != tc.wantUnusable {
				t.Fatalf("TLSA candidate=%s records=%d unusable=%v, want %s records=%d unusable=%v", result.Name, len(result.Records), result.UnusableRecords, wantName, wantRecords, tc.wantUnusable)
			}
		})
	}
}
