package mailclient

import (
	"bufio"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"gomail/config"
)

func TestSubmissionOversizedDATADrainFailureClosesConnection(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	p := &submissionSession{
		server: &Server{cfg: &config.Config{SMTP: config.SMTPConfig{MaxMessageSize: 12}, Clients: config.MailClientsConfig{ReadTimeout: 5, WriteTimeout: 5}}},
		conn:   server, reader: bufio.NewReader(server), writer: bufio.NewWriter(server),
		mailFrom: "alice@example.test", recipients: []string{"bob@example.test"},
	}
	done := make(chan struct{})
	go func() { p.handleDATA(); close(done) }()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(client)
	if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "354 ") {
		t.Fatalf("DATA prompt=%q err=%v", line, err)
	}
	// The first two lines exceed the message limit; the next line exceeds
	// the SMTP DATA line limit, leaving its tail unread.
	go func() {
		_, _ = client.Write([]byte("1234567890\r\n1234567890\r\n" + strings.Repeat("x", 1002) + "\r\n"))
	}()
	if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "552 ") {
		t.Fatalf("DATA rejection=%q err=%v", line, err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("DATA handler did not finish")
	}
	if _, err := r.ReadString('\n'); err == nil {
		t.Fatal("connection stayed open with unread DATA bytes")
	}
}

func TestSubmissionRejectsLFOnlyDATA(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	p := &submissionSession{server: &Server{cfg: &config.Config{SMTP: config.SMTPConfig{MaxMessageSize: 1024}, Clients: config.MailClientsConfig{ReadTimeout: 5}}}, conn: server, reader: bufio.NewReader(server)}
	done := make(chan error, 1)
	go func() { _, err := p.readData(); done <- err }()
	_ = client.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := client.Write([]byte("Subject: test\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, errInvalidDATAFraming) {
			t.Fatalf("LF-only DATA error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DATA reader did not reject LF-only framing")
	}
}

func TestPOP3SizeMatchesCanonicalMessage(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want int
	}{
		{raw: "A: b\n\nbody\n", want: len("A: b\r\n\r\nbody\r\n")},
		{raw: ".line\r\n", want: len(".line\r\n")},
		{raw: "no final CRLF", want: len("no final CRLF\r\n")},
	} {
		if got := pop3MessageOctets([]byte(test.raw)); got != test.want {
			t.Errorf("size(%q)=%d want %d", test.raw, got, test.want)
		}
	}
}
