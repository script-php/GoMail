package mailclient

import (
	"bufio"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gomail/config"
	"gomail/security"
	"gomail/store"
)

func TestSubmissionAcceptsPHPMailerDSNAndRejectsUnsupportedRCPTParameters(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "mail.db"), filepath.Join(t.TempDir(), "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	p := &submissionSession{server: &Server{db: db, cfg: &config.Config{SMTP: config.SMTPConfig{MaxRecipients: 10}, Clients: config.MailClientsConfig{WriteTimeout: 5}}}, conn: server, writer: bufio.NewWriter(server), mailFrom: "alice@example.test", greeted: true, ehlo: true}
	done := make(chan struct{})
	go func() {
		p.handleRCPT("TO:<bob@example.net> NOTIFY=SUCCESS,FAILURE,DELAY ORCPT=rfc822;old+40example.net")
		close(done)
	}()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "250 ") {
		t.Fatalf("RCPT response=%q err=%v", line, err)
	}
	<-done
	if len(p.recipients) != 1 || p.dsnNotify[0] != "SUCCESS,FAILURE,DELAY" || p.dsnOriginal[0] != "old@example.net" {
		t.Fatalf("DSN option not retained: recipients=%v notify=%v original=%v", p.recipients, p.dsnNotify, p.dsnOriginal)
	}
}

func TestSubmissionRepeatedRecipientDoesNotQueueTwice(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "mail.db"), filepath.Join(t.TempDir(), "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	p := &submissionSession{server: &Server{db: db, cfg: &config.Config{SMTP: config.SMTPConfig{MaxRecipients: 2}, Clients: config.MailClientsConfig{WriteTimeout: 5}}}, conn: server, writer: bufio.NewWriter(server), mailFrom: "alice@example.test", greeted: true, ehlo: true}
	reader := bufio.NewReader(client)
	for _, command := range []string{
		"TO:<Bob@example.net> NOTIFY=FAILURE",
		"TO:<Bob@EXAMPLE.NET> NOTIFY=SUCCESS",
		"TO:<bob@example.net> NOTIFY=DELAY",
	} {
		done := make(chan struct{})
		go func() { p.handleRCPT(command); close(done) }()
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "250 ") {
			t.Fatalf("RCPT %q response=%q err=%v", command, line, err)
		}
		<-done
	}
	if len(p.recipients) != 2 || p.recipients[0] != "Bob@example.net" || p.recipients[1] != "bob@example.net" {
		t.Fatalf("recipients=%v", p.recipients)
	}
	if len(p.dsnNotify) != 2 || p.dsnNotify[0] != "FAILURE" || p.dsnNotify[1] != "DELAY" {
		t.Fatalf("DSN options=%v", p.dsnNotify)
	}
}

func TestSubmissionRejectsInternationalizedRecipientWithoutSMTPUTF8(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	p := &submissionSession{server: &Server{cfg: &config.Config{SMTP: config.SMTPConfig{MaxRecipients: 10}, Clients: config.MailClientsConfig{WriteTimeout: 5}}}, conn: server, writer: bufio.NewWriter(server), mailFrom: "alice@example.test", greeted: true, ehlo: true}
	done := make(chan struct{})
	go func() { p.handleRCPT("TO:<josé@example.net>"); close(done) }()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "553 ") {
		t.Fatalf("RCPT response=%q err=%v", line, err)
	}
	<-done
	if len(p.recipients) != 0 {
		t.Fatalf("internationalized recipient queued: %v", p.recipients)
	}
}

func TestSubmissionDSNParameterParsing(t *testing.T) {
	for _, tc := range []struct {
		name, command, wantReply, wantReturn, wantEnvID string
	}{
		{"valid", "FROM:<alice@example.test> SIZE=42 RET=HDRS ENVID=order+20123", "250 ", "HDRS", "order 123"},
		{"duplicate size", "FROM:<alice@example.test> SIZE=42 SIZE=42", "501 ", "", ""},
		{"duplicate return", "FROM:<alice@example.test> RET=FULL RET=HDRS", "501 ", "", ""},
		{"invalid envelope ID", "FROM:<alice@example.test> ENVID=bad+0Avalue", "501 ", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			p := &submissionSession{server: &Server{cfg: &config.Config{SMTP: config.SMTPConfig{MaxMessageSize: 1000}, Clients: config.MailClientsConfig{WriteTimeout: 5}}}, conn: server, writer: bufio.NewWriter(server), greeted: true, ehlo: true, account: &store.Account{Email: "alice@example.test"}}
			done := make(chan struct{})
			go func() { p.handleMAIL(tc.command); close(done) }()
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			line, err := bufio.NewReader(client).ReadString('\n')
			if err != nil || !strings.HasPrefix(line, tc.wantReply) {
				t.Fatalf("MAIL response=%q err=%v", line, err)
			}
			<-done
			if p.dsnReturn != tc.wantReturn || p.dsnEnvID != tc.wantEnvID {
				t.Fatalf("DSN state return=%q envid=%q", p.dsnReturn, p.dsnEnvID)
			}
		})
	}
	if got, ok := parseSubmissionORCPT("rfc822;old+40example.net"); !ok || got != "old@example.net" {
		t.Fatalf("ORCPT=%q valid=%v", got, ok)
	}
	for _, value := range []string{"rfc822;bad+0Avalue", "rfc822;bad+GG", "unknown;old@example.net"} {
		if _, ok := parseSubmissionORCPT(value); ok {
			t.Errorf("accepted invalid ORCPT=%s", value)
		}
	}
}

func TestSubmissionNotifyValidation(t *testing.T) {
	for _, value := range []string{"NEVER", "SUCCESS", "FAILURE,DELAY"} {
		if _, ok := parseSubmissionNotify(value); !ok {
			t.Errorf("rejected valid NOTIFY=%s", value)
		}
	}
	for _, value := range []string{"", "NEVER,SUCCESS", "FAILURE,FAILURE", "BOGUS", "SUCCESS,"} {
		if _, ok := parseSubmissionNotify(value); ok {
			t.Errorf("accepted invalid NOTIFY=%s", value)
		}
	}
}

func TestSubmissionEHLOAdvertisesDSN(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	p := &submissionSession{server: &Server{cfg: &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test"}, SMTP: config.SMTPConfig{MaxMessageSize: 1024}, Clients: config.MailClientsConfig{WriteTimeout: 5}}}, conn: server, writer: bufio.NewWriter(server)}
	done := make(chan struct{})
	go func() { p.handleEHLO("client.example.test"); close(done) }()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	reader := bufio.NewReader(client)
	found := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		found = found || strings.Contains(line, "DSN")
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	<-done
	if !found {
		t.Fatal("EHLO did not advertise DSN")
	}
}

func TestSubmissionRejectsOverlongDATANow(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	p := &submissionSession{server: &Server{cfg: &config.Config{SMTP: config.SMTPConfig{MaxMessageSize: 10000}}}, conn: server, reader: bufio.NewReader(strings.NewReader(strings.Repeat("x", 999) + "\r\n.\r\n"))}
	if _, err := p.readData(); !errors.Is(err, security.ErrLineTooLong) {
		t.Fatalf("overlong DATA line accepted: %v", err)
	}
}

type countedSubmissionReader struct {
	reader *strings.Reader
	bytes  int
}

func (r *countedSubmissionReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytes += n
	return n, err
}

func TestSubmissionRejectsLongDATALineWithoutBufferingMessageLimit(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	input := &countedSubmissionReader{reader: strings.NewReader(strings.Repeat("x", 1<<20) + "\r\n.\r\n")}
	p := &submissionSession{server: &Server{cfg: &config.Config{SMTP: config.SMTPConfig{MaxMessageSize: 2 << 20}}}, conn: server, reader: bufio.NewReader(input)}
	if _, err := p.readData(); !errors.Is(err, security.ErrLineTooLong) {
		t.Fatalf("overlong DATA line error=%v", err)
	}
	if input.bytes > 8192 {
		t.Fatalf("read %d bytes before rejecting a line longer than 1000 octets", input.bytes)
	}
}

func TestSubmissionRejectsSecondMAILWithoutChangingEnvelope(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	p := &submissionSession{
		server: &Server{cfg: &config.Config{Clients: config.MailClientsConfig{WriteTimeout: 5}}},
		conn:   server, writer: bufio.NewWriter(server), greeted: true,
		account:  &store.Account{Email: "alice@example.test"},
		mailFrom: "alice@example.test", recipients: []string{"old@example.net"},
		dsnNotify: []string{"SUCCESS"},
	}
	done := make(chan struct{})
	go func() { p.handleMAIL("FROM:<other@example.test>"); close(done) }()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "503 ") {
		t.Fatalf("rejected MAIL response=%q err=%v", line, err)
	}
	<-done
	if p.mailFrom != "alice@example.test" || len(p.recipients) != 1 || p.recipients[0] != "old@example.net" || len(p.dsnNotify) != 1 || p.dsnNotify[0] != "SUCCESS" {
		t.Fatalf("rejected second MAIL changed the open transaction: from=%q recipients=%v notify=%v", p.mailFrom, p.recipients, p.dsnNotify)
	}
}

func TestSubmissionAllowsMaximumDotStuffedLine(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	wire := ".." + strings.Repeat("x", 997) + "\r\n.\r\n"
	p := &submissionSession{server: &Server{cfg: &config.Config{SMTP: config.SMTPConfig{MaxMessageSize: 10000}}}, conn: server, reader: bufio.NewReader(strings.NewReader(wire))}
	message, err := p.readData()
	if err != nil || string(message) != "."+strings.Repeat("x", 997)+"\r\n" {
		t.Fatalf("maximum dot-stuffed line rejected: len=%d err=%v", len(message), err)
	}
}

func TestSubmissionEncodingRequiresNegotiatedBodyMode(t *testing.T) {
	sevenBit := []byte("From: alice@example.test\r\n\r\nplain\r\n")
	eightBitBody := []byte("From: alice@example.test\r\n\r\ncaf\xc3\xa9\r\n")
	utf8Header := []byte("From: alice@example.test\r\nSubject: caf\xc3\xa9\r\n\r\nplain\r\n")
	if err := validateSubmissionEncoding(sevenBit, "7BIT"); err != nil {
		t.Fatal(err)
	}
	if err := validateSubmissionEncoding(sevenBit, ""); err != nil {
		t.Fatal(err)
	}
	if err := validateSubmissionEncoding(eightBitBody, "8BITMIME"); err != nil {
		t.Fatal(err)
	}
	if err := validateSubmissionEncoding(eightBitBody, ""); err == nil {
		t.Fatal("8-bit body accepted without BODY=8BITMIME")
	}
	if err := validateSubmissionEncoding(eightBitBody, "7BIT"); err == nil {
		t.Fatal("8-bit body accepted with explicit BODY=7BIT")
	}
	if err := validateSubmissionEncoding(utf8Header, "8BITMIME"); err == nil {
		t.Fatal("UTF-8 header accepted without SMTPUTF8 negotiation")
	}
}

func TestSubmissionStripsSenderSuppliedReturnPath(t *testing.T) {
	raw := []byte("From: alice@example.test\r\nReturn-Path: <forged@example.test>\r\n\tcontinued\r\nSubject: test\r\n\r\nbody\r\nReturn-Path: body text\r\n")
	got := stripHeader(raw, "return-path")
	if strings.Contains(string(got), "forged@example.test") || strings.Contains(string(got), "continued") || !strings.Contains(string(got), "Return-Path: body text") {
		t.Fatalf("Return-Path stripping changed wrong content: %q", got)
	}
}
