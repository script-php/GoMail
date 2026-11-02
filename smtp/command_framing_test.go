package smtp

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func TestInboundRejectsNonCRLFCommands(t *testing.T) {
	for _, tc := range []struct {
		name, command string
	}{
		{"LF only", "HELO remote.test\n"},
		{"embedded CR", "HELO remote\r.test\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()
			sess := NewSession(server, "mail.example.test", nil, nil, nil, 1024, 10, time.Second, time.Second, "", false, nil)
			inbound := &InboundServer{}
			done := make(chan struct{})
			go func() { inbound.runSession(sess); close(done) }()
			_ = client.SetDeadline(time.Now().Add(time.Second))
			reader := bufio.NewReader(client)
			if _, err := reader.ReadString('\n'); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Write([]byte(tc.command)); err != nil {
				t.Fatal(err)
			}
			response, err := reader.ReadString('\n')
			if err != nil || !strings.HasPrefix(response, "500 5.5.2 ") {
				t.Fatalf("response=%q err=%v", response, err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("connection not closed")
			}
		})
	}
}

func TestInboundAcceptsDSNLengthCommandLine(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	sess := NewSession(server, "mail.example.test", nil, nil, nil, 1024, 10, time.Second, time.Second, "", false, nil)
	done := make(chan struct{})
	go func() { (&InboundServer{}).runSession(sess); close(done) }()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	reader := bufio.NewReader(client)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	// RFC 3461 requires accepting at least 1036 octets, including CRLF.
	command := "NOOP " + strings.Repeat("x", 1029) + "\r\n"
	if len(command) != 1036 {
		t.Fatalf("command length=%d", len(command))
	}
	if _, err := client.Write([]byte(command)); err != nil {
		t.Fatal(err)
	}
	response, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(response, "250 ") {
		t.Fatalf("response=%q err=%v", response, err)
	}
	_ = client.Close()
	<-done
}
