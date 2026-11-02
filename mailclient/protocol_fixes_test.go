package mailclient

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"gomail/config"
	"gomail/store"
)

func protocolTestServer() *Server {
	return &Server{cfg: &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test"}, SMTP: config.SMTPConfig{MaxMessageSize: 16}, Clients: config.MailClientsConfig{ReadTimeout: 1, WriteTimeout: 1}}}
}

func protocolExchange(t *testing.T, handler func(net.Conn), command string) string {
	t.Helper()
	server, client := net.Pipe()
	defer client.Close()
	go handler(server)
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(client)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(client, command); err != nil {
		t.Fatal(err)
	}
	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestSubmissionHELODoesNotNegotiateExtensions(t *testing.T) {
	srv := protocolTestServer()
	server, client := net.Pipe()
	defer client.Close()
	go srv.handleSubmission(server)
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(client)
	_, _ = reader.ReadString('\n')
	for _, step := range []struct{ command, prefix string }{
		{"HELO bad_name.test\r\n", "501 "},
		{"HELO client.example.test\r\n", "250 "},
		{"STARTTLS\r\n", "503 "},
	} {
		_, _ = fmt.Fprint(client, step.command)
		response, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(response, step.prefix) {
			t.Fatalf("%q: response=%q err=%v", step.command, response, err)
		}
	}
	if !validSubmissionGreeting("[IPv6:2001:db8::1]", true) || validSubmissionGreeting("[IPv6:2001:db8::1]", false) {
		t.Fatal("EHLO/HELO address-literal validation failed")
	}
}

func TestSubmissionHELORejectsMailParameters(t *testing.T) {
	srv := protocolTestServer()
	server, client := net.Pipe()
	defer client.Close()
	p := &submissionSession{server: srv, conn: server, writer: bufio.NewWriter(server), greeted: true, account: &store.Account{Email: "alice@example.test"}}
	go p.handleMAIL("FROM:<alice@example.test> SIZE=10")
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	response, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || !strings.HasPrefix(response, "555 ") {
		t.Fatalf("response=%q err=%v", response, err)
	}
}

func TestIMAPAuthenticationResponseRequiresCRLF(t *testing.T) {
	srv := protocolTestServer()
	server, client := net.Pipe()
	defer client.Close()
	session := &imapSession{server: srv, conn: server, reader: bufio.NewReader(server), writer: bufio.NewWriter(server)}
	go session.authenticate("a9", []string{"PLAIN"})
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(client)
	if continuation, err := reader.ReadString('\n'); err != nil || continuation != "+\r\n" {
		t.Fatalf("continuation=%q err=%v", continuation, err)
	}
	_, _ = fmt.Fprint(client, "AGFsaWNlAHBhc3M=\n")
	response, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(response, "a9 BAD ") {
		t.Fatalf("response=%q err=%v", response, err)
	}
}

func TestIMAPAndPOP3RejectMalformedCommandFraming(t *testing.T) {
	srv := protocolTestServer()
	for _, tc := range []struct {
		name, command, prefix string
		handler               func(net.Conn)
	}{
		{"imap-lf", "a1 NOOP\n", "* BAD", srv.handleIMAP},
		{"imap-cr", "a1 NO\rOP\r\n", "* BAD", srv.handleIMAP},
		{"pop3-lf", "NOOP\n", "-ERR", srv.handlePOP3},
		{"pop3-cr", "NO\rOP\r\n", "-ERR", srv.handlePOP3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := protocolExchange(t, tc.handler, tc.command)
			if !strings.HasPrefix(response, tc.prefix) {
				t.Fatalf("response=%q", response)
			}
		})
	}
}

func TestIMAPOversizeLiteralHasTaggedCompletion(t *testing.T) {
	srv := protocolTestServer()
	response := protocolExchange(t, srv.handleIMAP, "a7 APPEND INBOX {17}\r\n")
	if !strings.HasPrefix(response, "a7 NO [TOOBIG]") {
		t.Fatalf("response=%q", response)
	}
}

func TestIMAPUnauthenticatedAppendRejectsBeforeLiteralContinuation(t *testing.T) {
	srv := protocolTestServer()
	server, client := net.Pipe()
	defer client.Close()
	go srv.handleIMAP(server)
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(client)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(client, "a1 APPEND INBOX {16}\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(response, "a1 NO ") {
		t.Fatalf("APPEND response=%q err=%v; expected tagged rejection, not literal continuation", response, err)
	}
	if _, err := fmt.Fprint(client, "a2 NOOP\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err = reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(response, "a2 OK ") {
		t.Fatalf("NOOP after rejected APPEND response=%q err=%v", response, err)
	}
}
