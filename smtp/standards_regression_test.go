package smtp

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
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
