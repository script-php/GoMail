package dns

import (
	"errors"
	"net"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestParseTLSARecordValidation(t *testing.T) {
	valid256 := strings.Repeat("ab", 32)
	valid512 := strings.Repeat("cd", 64)
	tests := []struct {
		name, input string
		ok          bool
	}{
		{"sha256", "3 1 1 " + valid256, true},
		{"sha512 split hex", "2 0 2 " + valid512[:64] + " " + valid512[64:], true},
		{"exact", "3 0 0 00ff", true},
		{"usage", "4 1 1 " + valid256, false},
		{"selector", "3 2 1 " + valid256, false},
		{"matching", "3 1 3 " + valid256, false},
		{"odd hex", "3 1 0 abc", false},
		{"non hex", "3 1 0 nope", false},
		{"empty", "3 1 0", false},
		{"wrong sha256 length", "3 1 1 ab", false},
		{"wrong sha512 length", "3 1 2 ab", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTLSARecord(tc.input)
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v err=%v", tc.ok, err)
			}
		})
	}
}

func TestTLSALookupDNSSECStates(t *testing.T) {
	valid := strings.Repeat("ab", 32)
	tests := []struct {
		name         string
		response     func(*mdns.Msg) *mdns.Msg
		wantErr      error
		wantRecords  int
		wantUnusable bool
		wantAnyErr   bool
	}{
		{
			name: "authenticated record",
			response: func(request *mdns.Msg) *mdns.Msg {
				response := new(mdns.Msg)
				response.SetReply(request)
				response.AuthenticatedData = true
				rr, _ := mdns.NewRR("_25._tcp.mail.example. 300 IN TLSA 3 1 1 " + valid)
				response.Answer = []mdns.RR{rr}
				return response
			},
			wantRecords: 1,
		},
		{
			name: "authenticated CNAME to TLSA",
			response: func(request *mdns.Msg) *mdns.Msg {
				response := new(mdns.Msg)
				response.SetReply(request)
				response.AuthenticatedData = true
				var rr mdns.RR
				if request.Question[0].Name == "_25._tcp.mail.example." {
					rr, _ = mdns.NewRR("_25._tcp.mail.example. 60 IN CNAME shared.example.")
				} else {
					rr, _ = mdns.NewRR("shared.example. 300 IN TLSA 3 1 1 " + valid)
				}
				response.Answer = []mdns.RR{rr}
				return response
			},
			wantRecords: 1,
		},
		{
			name: "authenticated CNAME and TLSA at same name",
			response: func(request *mdns.Msg) *mdns.Msg {
				response := new(mdns.Msg)
				response.SetReply(request)
				response.AuthenticatedData = true
				alias, _ := mdns.NewRR("_25._tcp.mail.example. 60 IN CNAME shared.example.")
				association, _ := mdns.NewRR("_25._tcp.mail.example. 60 IN TLSA 3 1 1 " + valid)
				response.Answer = []mdns.RR{alias, association}
				return response
			},
			wantAnyErr: true,
		},
		{
			name: "authenticated multiple CNAME targets",
			response: func(request *mdns.Msg) *mdns.Msg {
				response := new(mdns.Msg)
				response.SetReply(request)
				response.AuthenticatedData = true
				first, _ := mdns.NewRR("_25._tcp.mail.example. 60 IN CNAME one.example.")
				second, _ := mdns.NewRR("_25._tcp.mail.example. 60 IN CNAME two.example.")
				response.Answer = []mdns.RR{first, second}
				return response
			},
			wantAnyErr: true,
		},
		{
			name: "unrelated answer is not a TLSA association",
			response: func(request *mdns.Msg) *mdns.Msg {
				response := new(mdns.Msg)
				response.SetReply(request)
				response.AuthenticatedData = true
				rr, _ := mdns.NewRR("unrelated.example. 300 IN TLSA 3 1 1 " + valid)
				response.Answer = []mdns.RR{rr}
				return response
			},
			wantErr: ErrNoTLSA,
		},
		{
			name: "insecure CNAME target cannot provide TLSA",
			response: func(request *mdns.Msg) *mdns.Msg {
				response := new(mdns.Msg)
				response.SetReply(request)
				if request.Question[0].Name == "_25._tcp.mail.example." {
					response.AuthenticatedData = true
					rr, _ := mdns.NewRR("_25._tcp.mail.example. 60 IN CNAME shared.example.")
					response.Answer = []mdns.RR{rr}
				} else {
					rr, _ := mdns.NewRR("shared.example. 300 IN TLSA 3 1 1 " + valid)
					response.Answer = []mdns.RR{rr}
				}
				return response
			},
			wantErr: ErrDNSSECInsecure,
		},
		{
			name: "insecure record",
			response: func(request *mdns.Msg) *mdns.Msg {
				response := new(mdns.Msg)
				response.SetReply(request)
				rr, _ := mdns.NewRR("_25._tcp.mail.example. 300 IN TLSA 3 1 1 " + valid)
				response.Answer = []mdns.RR{rr}
				return response
			},
			wantErr: ErrDNSSECInsecure,
		},
		{
			name: "authenticated absence",
			response: func(request *mdns.Msg) *mdns.Msg {
				response := new(mdns.Msg)
				response.SetRcode(request, mdns.RcodeNameError)
				response.AuthenticatedData = true
				return response
			},
			wantErr: ErrNoTLSA,
		},
		{
			name: "authenticated malformed RRset",
			response: func(request *mdns.Msg) *mdns.Msg {
				response := new(mdns.Msg)
				response.SetReply(request)
				response.AuthenticatedData = true
				rr, _ := mdns.NewRR("_25._tcp.mail.example. 300 IN TLSA 3 1 1 ab")
				response.Answer = []mdns.RR{rr}
				return response
			},
			wantUnusable: true,
		},
		{
			name: "authenticated unsupported RRset",
			response: func(request *mdns.Msg) *mdns.Msg {
				response := new(mdns.Msg)
				response.SetReply(request)
				response.AuthenticatedData = true
				rr, _ := mdns.NewRR("_25._tcp.mail.example. 300 IN TLSA 9 1 1 " + valid)
				response.Answer = []mdns.RR{rr}
				return response
			},
			wantUnusable: true,
		},
		{
			name: "servfail without AD is lookup error",
			response: func(request *mdns.Msg) *mdns.Msg {
				response := new(mdns.Msg)
				response.SetRcode(request, mdns.RcodeServerFailure)
				return response
			},
			wantAnyErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := &mdns.Server{PacketConn: packetConn, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
				_ = w.WriteMsg(tc.response(request))
			})}
			go func() { _ = server.ActivateAndServe() }()
			defer server.Shutdown()

			result, lookupErr := queryTLSARecords("_25._tcp.mail.example.", packetConn.LocalAddr().String())
			if tc.wantAnyErr && lookupErr == nil {
				t.Fatal("expected DNS lookup error")
			}
			if !tc.wantAnyErr && !errors.Is(lookupErr, tc.wantErr) {
				t.Fatalf("error = %v, want %v", lookupErr, tc.wantErr)
			}
			if len(result.Records) != tc.wantRecords {
				t.Fatalf("records = %d, want %d", len(result.Records), tc.wantRecords)
			}
			if result.UnusableRecords != tc.wantUnusable {
				t.Fatalf("unusable = %v, want %v", result.UnusableRecords, tc.wantUnusable)
			}
		})
	}
}
