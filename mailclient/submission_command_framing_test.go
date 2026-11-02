package mailclient

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"gomail/config"
)

func TestSubmissionRejectsNonCRLFCommands(t *testing.T) {
	for _, command := range []string{"EHLO remote.test\n", "EHLO remote\r.test\r\n"} {
		server, client := net.Pipe()
		s := &Server{cfg: &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test"}, Clients: config.MailClientsConfig{ReadTimeout: 1, WriteTimeout: 1}}}
		done := make(chan struct{})
		go func() { s.handleSubmission(server); close(done) }()
		_ = client.SetDeadline(time.Now().Add(time.Second))
		reader := bufio.NewReader(client)
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write([]byte(command)); err != nil {
			t.Fatal(err)
		}
		response, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(response, "500 ") {
			t.Fatalf("command=%q response=%q err=%v", command, response, err)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("connection not closed")
		}
		_ = client.Close()
	}
}

func TestSubmissionAcceptsDSNLengthCommandLine(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	s := &Server{cfg: &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test"}, Clients: config.MailClientsConfig{ReadTimeout: 1, WriteTimeout: 1}}}
	done := make(chan struct{})
	go func() { s.handleSubmission(server); close(done) }()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	reader := bufio.NewReader(client)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	command := "NOOP " + strings.Repeat("x", 1029) + "\r\n"
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

func TestSubmissionRejectsNonCRLFAuthResponse(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	p := &submissionSession{server: &Server{cfg: &config.Config{Clients: config.MailClientsConfig{ReadTimeout: 1, WriteTimeout: 1}}}, conn: server, reader: bufio.NewReader(server), writer: bufio.NewWriter(server)}
	done := make(chan bool, 1)
	go func() { _, ok := p.readAuthLine(); done <- ok }()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	if _, err := client.Write([]byte("YWxpY2U=\n")); err != nil {
		t.Fatal(err)
	}
	response, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || !strings.HasPrefix(response, "501 ") {
		t.Fatalf("response=%q err=%v", response, err)
	}
	if <-done {
		t.Fatal("accepted LF-only AUTH response")
	}
}

func TestSubmissionClosesOnOverlongAuthResponse(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	p := &submissionSession{server: &Server{cfg: &config.Config{Clients: config.MailClientsConfig{ReadTimeout: 1}}}, conn: server, reader: bufio.NewReader(server)}
	done := make(chan bool, 1)
	go func() { _, ok := p.readAuthLine(); done <- ok }()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = client.Write([]byte(strings.Repeat("A", 1001) + "\r\nNOOP\r\n"))
	if <-done {
		t.Fatal("accepted overlong AUTH response")
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection remained open after overlong AUTH response")
	}
}

func TestSubmissionMultilineReplyHasWriteDeadline(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	p := &submissionSession{server: &Server{cfg: &config.Config{Clients: config.MailClientsConfig{WriteTimeout: 1}}}, conn: server, writer: bufio.NewWriter(server)}
	done := make(chan struct{})
	go func() { p.replyMulti(250, []string{"example.test", "DSN"}); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("multiline reply blocked without a write deadline")
	}
}
