package smtp

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestHELOAddressLiterals(t *testing.T) {
	s := &Session{}
	for _, name := range []string{"[192.0.2.1]", "[IPv6:2001:db8::1]"} {
		if err := s.validateHeloEhlo(name); err != nil {
			t.Errorf("valid literal %s: %v", name, err)
		}
	}
	for _, name := range []string{"[2001:db8::1]", "[IPv6:not-an-address]", "[IPv6:192.0.2.1]"} {
		if err := s.validateHeloEhlo(name); err == nil {
			t.Errorf("invalid literal accepted: %s", name)
		}
	}
	for _, name := range []string{"bad_name.example", "bad!name.example", "éxample.test"} {
		if err := s.validateHeloEhlo(name); err == nil {
			t.Errorf("invalid domain accepted: %s", name)
		}
	}
}

func TestMAILRejectsMalformedReversePath(t *testing.T) {
	for _, path := range []string{"not-an-address", "bad@@example.test", "name <user@example.test>"} {
		server, client := net.Pipe()
		s := &Session{conn: server, writer: bufio.NewWriter(server), state: StateReady, greeted: true, esmtp: true, writeTimeout: time.Second}
		done := make(chan struct{})
		go func() { s.handleMAIL("FROM:<" + path + ">"); close(done) }()
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		reply, err := bufio.NewReader(client).ReadString('\n')
		if err != nil || !strings.HasPrefix(reply, "501 ") || s.mailFrom != "" {
			t.Errorf("path %q accepted: reply=%q sender=%q err=%v", path, reply, s.mailFrom, err)
		}
		<-done
		server.Close()
		client.Close()
	}
}

func TestOversizedDATAReceivesPermanentSizeReply(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, reader: bufio.NewReader(server), writer: bufio.NewWriter(server), state: StateRcpt, rcptTo: []string{"user@example.test"}, maxSize: 16, readTimeout: time.Second, writeTimeout: time.Second}
	done := make(chan struct{})
	go func() { s.handleDATA(); close(done) }()
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	if reply, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(reply, "354 ") {
		t.Fatalf("DATA invitation = %q, %v", reply, err)
	}
	if _, err := client.Write([]byte("Subject: much-too-long-for-limit\r\n")); err != nil {
		t.Fatal(err)
	}
	if reply, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(reply, "552 5.3.4 ") {
		t.Fatalf("oversized DATA reply = %q, %v", reply, err)
	}
	<-done
	if s.state != StateQuit || s.data.Len() != 0 {
		t.Fatal("oversized DATA left a reusable transaction")
	}
}

func TestDATARejectsEmbeddedCarriageReturn(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, reader: bufio.NewReader(server), writer: bufio.NewWriter(server), state: StateRcpt, rcptTo: []string{"user@example.test"}, maxSize: 1024, readTimeout: time.Second, writeTimeout: time.Second}
	done := make(chan struct{})
	go func() { s.handleDATA(); close(done) }()
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	if reply, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(reply, "354 ") {
		t.Fatalf("DATA invitation = %q, %v", reply, err)
	}
	if _, err := client.Write([]byte("Subject: first\rsecond\r\n")); err != nil {
		t.Fatal(err)
	}
	if reply, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(reply, "554 5.6.0 ") {
		t.Fatalf("malformed DATA reply = %q, %v", reply, err)
	}
	<-done
	if s.state != StateQuit || s.data.Len() != 0 {
		t.Fatal("malformed DATA left a reusable transaction")
	}
}

func TestRecipientLookupErrorIsTemporary(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, writer: bufio.NewWriter(server), state: StateMail, domains: []string{"example.test"}, mailFrom: "sender@remote.test", accountExists: func(string) (bool, error) { return false, errors.New("database unavailable") }, writeTimeout: time.Second}
	done := make(chan struct{})
	go func() { s.handleRCPT("TO:<alice@example.test>"); close(done) }()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	reply, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || !strings.HasPrefix(reply, "451 4.3.0") {
		t.Fatalf("RCPT reply %q: %v", reply, err)
	}
	<-done
}

func TestSMTPUTF8RecipientUnicodeDomainRoutesToHostedALabel(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	const canonical = "alice@xn--bcher-kva.example"
	lookup := func(address string) (bool, error) { return address == canonical, nil }
	s := &Session{conn: server, writer: bufio.NewWriter(server), state: StateMail, domains: []string{"xn--bcher-kva.example"}, smtputf8Enabled: true, accountExists: lookup, maxRcpt: 100, writeTimeout: time.Second}
	for _, recipient := range []string{"alice@bücher.example", canonical} {
		done := make(chan struct{})
		go func() { s.handleRCPT("TO:<" + recipient + ">"); close(done) }()
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		reply, err := bufio.NewReader(client).ReadString('\n')
		if err != nil || !strings.HasPrefix(reply, "250 ") {
			t.Fatalf("RCPT %q reply %q: %v", recipient, reply, err)
		}
		<-done
	}
	if len(s.rcptTo) != 1 || s.rcptTo[0] != canonical {
		t.Fatalf("canonical recipients = %v", s.rcptTo)
	}
}

func TestFailedSTARTTLSClosesSMTPConnection(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	s := &Session{conn: server, reader: bufio.NewReader(server), writer: bufio.NewWriter(server), state: StateReady, greeted: true, esmtp: true, tlsConfig: &tls.Config{MinVersion: tls.VersionTLS12}, writeTimeout: time.Second}
	done := make(chan struct{})
	go func() { s.handleSTARTTLS(); close(done) }()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "220 ") {
		t.Fatalf("STARTTLS reply %q: %v", line, err)
	}
	if _, err := client.Write([]byte("NOOP\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("TLS handshake did not terminate")
	}
	if s.state != StateQuit {
		t.Fatal("failed TLS handshake left SMTP session active")
	}
	if _, err := client.Write([]byte("MAIL FROM:<a@example.com>\r\n")); err == nil {
		t.Fatal("plaintext command accepted after failed TLS handshake")
	}
}

func TestBDATHugeIncompleteChunkTimesOutWithoutAllocation(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, reader: bufio.NewReader(server), writer: bufio.NewWriter(server), state: StateRcpt, esmtp: true, maxSize: 1024, readTimeout: 20 * time.Millisecond, writeTimeout: time.Second}
	done := make(chan struct{})
	go func() { s.handleBDAT("9223372036854775807 LAST"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("incomplete BDAT did not hit its read deadline")
	}
	if s.state != StateQuit || s.data.Len() != 0 {
		t.Fatal("incomplete huge chunk left session usable")
	}
}

func TestDataLineBoundedAcrossReaderBuffers(t *testing.T) {
	s := &Session{reader: bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 10000)+"\r\n"), 32)}
	line, err := s.readDataLine(10002)
	if err != nil || len(line) != 10002 {
		t.Fatalf("long bounded line: len=%d err=%v", len(line), err)
	}
	s.reader = bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 10000)), 32)
	if _, err := s.readDataLine(100); err == nil {
		t.Fatal("unbounded line accepted")
	}
}

func TestESMTPParameterParsing(t *testing.T) {
	quoted := `FROM:<"a>b"@example.test> SIZE=12`
	if got := extractAddress(quoted, "FROM:"); got != `"a>b"@example.test` {
		t.Fatalf("quoted local-part truncated: %q", got)
	}
	if params, err := parseESMTPParameters(quoted); err != nil || params["SIZE"] != "12" {
		t.Fatalf("quoted local-part parameters=%v err=%v", params, err)
	}
	if got := extractAddress(`TO:<"a\\\"b>c"@example.test>`, "TO:"); got != `"a\\\"b>c"@example.test` {
		t.Fatalf("escaped quote in local-part truncated: %q", got)
	}
	if got := extractAddress(`TO:<"unterminated@example.test>`, "TO:"); got != "" {
		t.Fatalf("accepted unterminated quoted path: %q", got)
	}
	params, err := parseESMTPParameters("FROM:<a@example> SMTPUTF8 BODY=8BITMIME SIZE=123")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := params["SMTPUTF8"]; !ok || params["BODY"] != "8BITMIME" || params["SIZE"] != "123" {
		t.Fatalf("bad params: %#v", params)
	}
	if _, err = parseESMTPParameters("FROM:<a@example> SIZE=1 SIZE=2"); err == nil {
		t.Fatal("duplicate parameter accepted")
	}
	for _, malformed := range []string{"FROM:<a@example>SIZE=1", "TO:<a@example>NOTIFY=FAILURE", "FROM:<a@example>\tSIZE=1"} {
		if _, err = parseESMTPParameters(malformed); err == nil {
			t.Fatalf("accepted parameter without required space: %q", malformed)
		}
	}
	for _, value := range []string{"NEVER", "SUCCESS,FAILURE", "FAILURE,DELAY"} {
		if !validNotify(value) {
			t.Errorf("rejected %s", value)
		}
	}
	for _, value := range []string{"", "NEVER,FAILURE", "FAILURE,FAILURE", "BOGUS"} {
		if validNotify(value) {
			t.Errorf("accepted %s", value)
		}
	}
}
