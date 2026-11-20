package dns

import (
	"errors"
	"net"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestLookupMXDoesNotFallBackAfterTemporaryError(t *testing.T) {
	InitCache(60)
	oldMX, oldHost := lookupMX, lookupHost
	t.Cleanup(func() { lookupMX, lookupHost = oldMX, oldHost })
	lookupMX = func(string) ([]*net.MX, error) {
		return nil, &net.DNSError{Err: "temporary failure", IsTemporary: true}
	}
	called := false
	lookupHost = func(string) ([]string, error) { called = true; return []string{"192.0.2.1"}, nil }
	if _, err := LookupMX("temporary.example"); err == nil || called {
		t.Fatalf("temporary MX failure fell back to A/AAAA: err=%v called=%v", err, called)
	}
}

func TestAuthenticatedMXRequiresDNSSECThroughCNAME(t *testing.T) {
	for _, secureTarget := range []bool{false, true} {
		packet, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := &mdns.Server{PacketConn: packet, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
			response := new(mdns.Msg)
			response.SetReply(req)
			name := req.Question[0].Name
			response.AuthenticatedData = name == "example.test." || secureTarget
			if name == "example.test." {
				rr, _ := mdns.NewRR("example.test. 60 IN CNAME mx-zone.test.")
				response.Answer = []mdns.RR{rr}
			} else {
				rr, _ := mdns.NewRR("mx-zone.test. 60 IN MX 10 mail.mx-zone.test.")
				response.Answer = []mdns.RR{rr}
			}
			_ = w.WriteMsg(response)
		})}
		go func() { _ = server.ActivateAndServe() }()
		records, err := queryAuthenticatedMX("example.test", packet.LocalAddr().String())
		_ = server.Shutdown()
		if secureTarget {
			if err != nil || len(records) != 1 || records[0].Host != "mail.mx-zone.test" {
				t.Fatalf("secure CNAME chain: records=%+v err=%v", records, err)
			}
		} else if !errors.Is(err, ErrDNSSECInsecure) {
			t.Fatalf("insecure CNAME target was accepted: records=%+v err=%v", records, err)
		}
	}
}

func TestAuthenticatedMXRejectsContradictoryCNAMEAnswer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers []string
	}{
		{"CNAME with MX", []string{"example.test. 60 IN CNAME alias.example.test.", "example.test. 60 IN MX 10 mx.example.test."}},
		{"multiple CNAMEs", []string{"example.test. 60 IN CNAME one.example.test.", "example.test. 60 IN CNAME two.example.test."}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := &mdns.Server{PacketConn: packet, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
				response := new(mdns.Msg)
				response.SetReply(req)
				response.AuthenticatedData = true
				for _, text := range tc.answers {
					rr, _ := mdns.NewRR(text)
					response.Answer = append(response.Answer, rr)
				}
				_ = w.WriteMsg(response)
			})}
			go func() { _ = server.ActivateAndServe() }()
			defer server.Shutdown()
			_, err = queryAuthenticatedMX("example.test", packet.LocalAddr().String())
			if err == nil || errors.Is(err, ErrNoMailRoute) || errors.Is(err, ErrNullMX) {
				t.Fatalf("contradictory CNAME answer was accepted or made permanent: %v", err)
			}
		})
	}
}

func TestLookupMXImplicitAndNullMX(t *testing.T) {
	InitCache(60)
	oldMX, oldHost := lookupMX, lookupHost
	t.Cleanup(func() { lookupMX, lookupHost = oldMX, oldHost })
	lookupHost = func(string) ([]string, error) { return []string{"192.0.2.2"}, nil }
	lookupMX = func(string) ([]*net.MX, error) {
		return nil, &net.DNSError{Err: "no MX", IsNotFound: true}
	}
	records, err := LookupMX("implicit.example")
	if err != nil || len(records) != 1 || records[0].Host != "implicit.example" {
		t.Fatalf("implicit MX result: %+v %v", records, err)
	}
	lookupMX = func(string) ([]*net.MX, error) { return []*net.MX{{Host: ".", Pref: 0}}, nil }
	if _, err := LookupMX("null.example"); !errors.Is(err, ErrNullMX) {
		t.Fatalf("null MX result: %v", err)
	}
}

func TestContradictoryNullMXIsRetryable(t *testing.T) {
	InitCache(60)
	oldMX := lookupMX
	t.Cleanup(func() { lookupMX = oldMX })
	for _, tc := range []struct {
		name    string
		records []*net.MX
	}{
		{"mixed", []*net.MX{{Host: ".", Pref: 0}, {Host: "mx.example.test.", Pref: 10}}},
		{"wrong preference", []*net.MX{{Host: ".", Pref: 10}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookupMX = func(string) ([]*net.MX, error) { return tc.records, nil }
			_, err := LookupMX(tc.name + ".example.test")
			if !errors.Is(err, errMalformedNullMX) || errors.Is(err, ErrNullMX) {
				t.Fatalf("contradictory null MX classified as permanent: %v", err)
			}
		})
	}
}

func TestAuthenticatedContradictoryNullMXIsRetryable(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{PacketConn: packet, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(req)
		response.AuthenticatedData = true
		for _, text := range []string{"example.test. 60 IN MX 0 .", "example.test. 60 IN MX 10 mx.example.test."} {
			rr, _ := mdns.NewRR(text)
			response.Answer = append(response.Answer, rr)
		}
		_ = w.WriteMsg(response)
	})}
	go func() { _ = server.ActivateAndServe() }()
	defer server.Shutdown()
	_, err = queryAuthenticatedMX("example.test", packet.LocalAddr().String())
	if !errors.Is(err, errMalformedNullMX) || errors.Is(err, ErrNullMX) {
		t.Fatalf("authenticated contradictory null MX classified as permanent: %v", err)
	}
}

func TestLookupMXNoRouteIsPermanentButDNSFailureIsTemporary(t *testing.T) {
	InitCache(60)
	oldMX, oldHost := lookupMX, lookupHost
	t.Cleanup(func() { lookupMX, lookupHost = oldMX, oldHost })
	lookupMX = func(string) ([]*net.MX, error) {
		return nil, &net.DNSError{Err: "no MX", IsNotFound: true}
	}
	lookupHost = func(string) ([]string, error) {
		return nil, &net.DNSError{Err: "no address", IsNotFound: true}
	}
	if _, err := LookupMX("no-route.example"); !errors.Is(err, ErrNoMailRoute) {
		t.Fatalf("confirmed absence was not permanent: %v", err)
	}
	lookupHost = func(string) ([]string, error) {
		return nil, &net.DNSError{Err: "SERVFAIL", IsTemporary: true}
	}
	if _, err := LookupMX("address-timeout.example"); err == nil || errors.Is(err, ErrNoMailRoute) {
		t.Fatalf("temporary address failure became permanent: %v", err)
	}
	lookupMX = func(string) ([]*net.MX, error) { return nil, nil }
	lookupHost = func(string) ([]string, error) { return nil, nil }
	if _, err := LookupMX("empty-address.example"); !errors.Is(err, ErrNoMailRoute) {
		t.Fatalf("empty MX and address answers were not permanent: %v", err)
	}
}

func TestAuthenticatedImplicitMXRequiresAddress(t *testing.T) {
	for _, tc := range []struct {
		name, addressAnswer string
		addressRcode        int
		wantRoute           bool
	}{
		{"secure address", "A", mdns.RcodeSuccess, true},
		{"secure no address", "", mdns.RcodeSuccess, false},
		{"secure nonexistent name", "", mdns.RcodeNameError, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := &mdns.Server{PacketConn: packet, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
				response := new(mdns.Msg)
				response.SetReply(req)
				response.AuthenticatedData = true
				if req.Question[0].Qtype == mdns.TypeA {
					response.Rcode = tc.addressRcode
					if tc.addressAnswer == "A" {
						rr, _ := mdns.NewRR("implicit.example. 60 IN A 192.0.2.3")
						response.Answer = []mdns.RR{rr}
					}
				}
				_ = w.WriteMsg(response)
			})}
			go func() { _ = server.ActivateAndServe() }()
			defer server.Shutdown()
			records, err := queryAuthenticatedMX("implicit.example", packet.LocalAddr().String())
			if tc.wantRoute {
				if err != nil || len(records) != 1 || records[0].Host != "implicit.example" {
					t.Fatalf("implicit MX route=%v err=%v", records, err)
				}
			} else if !errors.Is(err, ErrNoMailRoute) {
				t.Fatalf("confirmed no-route result=%v err=%v", records, err)
			}
		})
	}
}

func TestShuffleMXPreferencesPreservesPriorityGroups(t *testing.T) {
	records := []MXRecord{
		{Host: "a", Pref: 10}, {Host: "b", Pref: 10}, {Host: "c", Pref: 10},
		{Host: "d", Pref: 20}, {Host: "e", Pref: 20},
	}
	shuffleMXPreferences(records, func(int) int { return 0 })
	for i, pref := range []uint16{10, 10, 10, 20, 20} {
		if records[i].Pref != pref {
			t.Fatalf("preference order changed: %+v", records)
		}
	}
	if records[0].Host == "a" && records[1].Host == "b" && records[2].Host == "c" {
		t.Fatalf("equal-preference hosts were not shuffled: %+v", records)
	}
	if records[3].Host == "d" && records[4].Host == "e" {
		t.Fatalf("second preference group was not shuffled: %+v", records)
	}
}
