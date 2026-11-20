package dns

import (
	"net"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestDomainExistsDistinguishesNXDOMAINFromNODATA(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{PacketConn: packet, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(request)
		if request.Question[0].Name == "missing.example.test." {
			response.Rcode = mdns.RcodeNameError
		}
		_ = w.WriteMsg(response)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	for _, tc := range []struct {
		name, domain string
		exists       bool
	}{
		{"NOERROR NODATA", "existing.example.test", true},
		{"NXDOMAIN", "missing.example.test", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exists, err := queryDomainExists(tc.domain, packet.LocalAddr().String())
			if err != nil || exists != tc.exists {
				t.Fatalf("exists=%v err=%v", exists, err)
			}
		})
	}
}
