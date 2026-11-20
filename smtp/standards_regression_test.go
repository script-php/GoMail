package smtp

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"gomail/parser"
)

func TestRejectedMAILDropsExtensionState(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, writer: bufio.NewWriter(server), state: StateReady, greeted: true, esmtp: true, maxSize: 10000, writeTimeout: time.Second}
	reader := bufio.NewReader(client)
	try := func(arg, want string) {
		t.Helper()
		done := make(chan struct{})
		go func() { s.handleMAIL(arg); close(done) }()
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		reply, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(reply, want) {
			t.Fatalf("MAIL %q reply=%q err=%v", arg, reply, err)
		}
		<-done
	}
	try("FROM:<sender@example.test> SMTPUTF8 ENVID=bad+", "501 ")
	if s.smtputf8Enabled || s.state != StateReady {
		t.Fatal("rejected MAIL modified transaction state")
	}
	try("FROM:<josé@example.test>", "553 ")
}

func TestDSNParameterBoundsAndEnvelopeIDCharacters(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, writer: bufio.NewWriter(server), state: StateReady, greeted: true, esmtp: true, maxSize: 10000, writeTimeout: time.Second}
	s.dsnNotify = make(map[string]string)
	s.dsnOriginalRcpt = make(map[string]string)
	reader := bufio.NewReader(client)
	try := func(command func(), want string) {
		t.Helper()
		done := make(chan struct{})
		go func() { command(); close(done) }()
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		reply, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(reply, want) {
			t.Fatalf("reply=%q err=%v, want %q", reply, err, want)
		}
		<-done
	}
	try(func() { s.handleMAIL("FROM:<a@example.test> ENVID=" + strings.Repeat("a", 101)) }, "501 ")
	try(func() { s.handleMAIL("FROM:<a@example.test> ENVID=bad+0D+0Ainjected") }, "501 ")
	try(func() { s.handleMAIL("FROM:<a@example.test> ENVID=" + strings.Repeat("a", 100)) }, "250 ")
	if len(s.dsnEnvID) != 100 {
		t.Fatalf("valid ENVID lost: %q", s.dsnEnvID)
	}
	s.domains = []string{"example.test"}
	s.accountExists = func(string) (bool, error) { return true, nil }
	s.maxRcpt = 10
	try(func() { s.handleRCPT("TO:<b@example.test> ORCPT=rfc822;" + strings.Repeat("a", 494)) }, "501 ")
	try(func() { s.handleRCPT("TO:<b@example.test> ORCPT=rfc822;" + strings.Repeat("a", 493)) }, "250 ")
}

func TestUnqualifiedPostmasterRecipientUsesServerDomain(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, writer: bufio.NewWriter(server), state: StateMail, mailFrom: "sender@remote.test", domains: []string{"example.test"}, postmasterDomain: "example.test", accountExists: func(address string) (bool, error) { return address == "postmaster@example.test", nil }, maxRcpt: 10, writeTimeout: time.Second}
	done := make(chan struct{})
	go func() { s.handleRCPT("TO:<PoStMaStEr>"); close(done) }()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	reply, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || !strings.HasPrefix(reply, "250 ") {
		t.Fatalf("postmaster reply=%q err=%v", reply, err)
	}
	<-done
	if len(s.rcptTo) != 1 || s.rcptTo[0] != "postmaster@example.test" {
		t.Fatalf("recipients=%v", s.rcptTo)
	}
}

func TestInboundRejectsHeaderStyleEnvelopeRecipient(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, writer: bufio.NewWriter(server), state: StateMail, mailFrom: "sender@remote.test", domains: []string{"example.test"}, accountExists: func(string) (bool, error) { return true, nil }, maxRcpt: 10, writeTimeout: time.Second}
	for _, command := range []string{
		"TO:<bob(comment)@example.test>",
		"TO:< bob@example.test>",
	} {
		done := make(chan struct{})
		go func() { s.handleRCPT(command); close(done) }()
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		reply, err := bufio.NewReader(client).ReadString('\n')
		if err != nil || !strings.HasPrefix(reply, "553 ") {
			t.Fatalf("RCPT %q reply=%q err=%v", command, reply, err)
		}
		<-done
	}
	if len(s.rcptTo) != 0 {
		t.Fatalf("invalid recipients accepted: %v", s.rcptTo)
	}
}

func TestInboundRecipientDedupUsesGoMailCaseInsensitivePolicy(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, writer: bufio.NewWriter(server), state: StateMail, mailFrom: "sender@remote.test", domains: []string{"example.test"}, accountExists: func(string) (bool, error) { return true, nil }, maxRcpt: 10, writeTimeout: time.Second}
	reader := bufio.NewReader(client)
	for _, address := range []string{"Bob@example.test", "Bob@EXAMPLE.TEST", "bob@example.test"} {
		done := make(chan struct{})
		go func() { s.handleRCPT("TO:<" + address + ">"); close(done) }()
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		reply, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(reply, "250 ") {
			t.Fatalf("RCPT %q reply=%q err=%v", address, reply, err)
		}
		<-done
	}
	if len(s.rcptTo) != 1 || s.rcptTo[0] != "Bob@example.test" {
		t.Fatalf("recipients=%v", s.rcptTo)
	}
}

func TestSPFIdentityDomainUsesFinalAt(t *testing.T) {
	if got := spfIdentityDomain(`"sender@desk"@example.test`, "helo.example.test"); got != "example.test" {
		t.Fatalf("SPF identity domain=%q", got)
	}
}

func TestInboundDATARejectsNoncanonicalFraming(t *testing.T) {
	for _, tc := range []struct{ name, data, want string }{
		{"LF-only terminator", "Subject: x\r\n\r\nbody\r\n.\n", "554 "},
		{"overlong line", "Subject: x\r\n\r\n" + strings.Repeat("x", 999) + "\r\n.\r\n", "552 "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			s := &Session{conn: server, reader: bufio.NewReader(strings.NewReader(tc.data)), writer: bufio.NewWriter(server), state: StateRcpt, rcptTo: []string{"alice@example.test"}, maxSize: 10000, writeTimeout: time.Second, readTimeout: time.Second}
			done := make(chan struct{})
			go func() { s.handleDATA(); close(done) }()
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			reader := bufio.NewReader(client)
			if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "354 ") {
				t.Fatalf("DATA greeting=%q err=%v", line, err)
			}
			if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, tc.want) {
				t.Fatalf("DATA final=%q err=%v", line, err)
			}
			<-done
			if s.state != StateQuit {
				t.Fatal("invalid DATA left connection synchronized")
			}
		})
	}
}

func TestBDATRejectsNoncanonicalText(t *testing.T) {
	s := &Session{}
	s.data.WriteString("Subject: x\r\n\r\nbody\n")
	if err := s.validateMessageEncoding(); err == nil {
		t.Fatal("accepted bare LF in BDAT content without BINARYMIME")
	}
	s.data.Reset()
	s.data.WriteString("Subject: x\r\n\r\nbody\x00\r\n")
	if err := s.validateMessageEncoding(); err == nil {
		t.Fatal("accepted NUL in BDAT content without BINARYMIME")
	}
}

func TestInboundAcceptsHeaderOnlyMessage(t *testing.T) {
	raw := "From: sender@example.test\r\nTo: recipient@example.test\r\nAuthentication-Results: forged.example; dkim=pass\r\nSubject: headers only\r\n"
	s := &Session{}
	s.data.WriteString(raw)
	if err := s.validateMessageEncoding(); err != nil {
		t.Fatalf("valid header-only message rejected: %v", err)
	}
	cleaned, err := RemoveExternalAuthenticationResults([]byte(raw))
	if err != nil {
		t.Fatalf("header-only authentication cleanup failed: %v", err)
	}
	if strings.Contains(string(cleaned), "forged.example") {
		t.Fatal("untrusted authentication result was retained")
	}
	final, err := FinalDeliveryReturnPath(cleaned, "sender@example.test")
	if err != nil {
		t.Fatalf("header-only final delivery failed: %v", err)
	}
	parsed, err := parser.Parse(final)
	if err != nil {
		t.Fatalf("header-only message cannot be parsed: %v", err)
	}
	if parsed.Subject != "headers only" || parsed.TextBody != "" {
		t.Fatalf("parsed subject=%q body=%q", parsed.Subject, parsed.TextBody)
	}
	s.data.Reset()
	s.data.WriteString("Subject: unterminated")
	if err := s.validateMessageEncoding(); err == nil {
		t.Fatal("accepted unterminated header section")
	}
}

func TestInboundMalformedMessageGetsPermanentFailure(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, writer: bufio.NewWriter(server), writeTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		(&InboundServer{}).sendProcessingError(s, fmt.Errorf("parse: %w", errInvalidMessage))
		close(done)
	}()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	reply, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || !strings.HasPrefix(reply, "554 5.6.0 ") {
		t.Fatalf("malformed message reply=%q err=%v", reply, err)
	}
	<-done
}

func TestRFC822ORCPTRejectsEncodedNonASCII(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, writer: bufio.NewWriter(server), state: StateMail, esmtp: true, mailFrom: "sender@remote.test", domains: []string{"example.test"}, accountExists: func(string) (bool, error) { return true, nil }, writeTimeout: time.Second}
	done := make(chan struct{})
	go func() { s.handleRCPT("TO:<alice@example.test> ORCPT=rfc822;jos+E9@example.test"); close(done) }()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	reply, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || !strings.HasPrefix(reply, "501 ") {
		t.Fatalf("ORCPT reply=%q err=%v", reply, err)
	}
	<-done
}
