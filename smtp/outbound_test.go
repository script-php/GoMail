package smtp

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gomail/auth"
	"gomail/dns"
	"gomail/mta_sts"
	"gomail/store"
)

func TestDANETransportPolicy(t *testing.T) {
	usable := dns.TLSAResult{Authenticated: true, Records: []dns.TLSARecord{{Usage: 3, Selector: 1, MatchingType: 1, CertData: strings.Repeat("ab", 32)}}}
	unusable := dns.TLSAResult{Authenticated: true, UnusableRecords: true}
	for _, tc := range []struct {
		name, mode      string
		result          dns.TLSAResult
		lookupErr       error
		tls, auth, fail bool
	}{
		{"optional usable", "optional", usable, nil, true, true, false},
		{"optional unusable", "optional", unusable, nil, true, false, false},
		{"optional insecure", "optional", dns.TLSAResult{}, dns.ErrDNSSECInsecure, false, false, false},
		{"optional timeout", "optional", dns.TLSAResult{}, errors.New("timeout"), false, false, true},
		{"required unusable", "required", unusable, nil, false, false, true},
		{"required insecure", "required", dns.TLSAResult{}, dns.ErrDNSSECInsecure, false, false, true},
		{"disabled", "disabled", usable, errors.New("timeout"), false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireTLS, authenticate, err := daneTransportPolicy(tc.mode, tc.result, tc.lookupErr)
			if requireTLS != tc.tls || authenticate != tc.auth || (err != nil) != tc.fail {
				t.Fatalf("got TLS=%v auth=%v err=%v", requireTLS, authenticate, err)
			}
		})
	}
}

func TestRecipientCommandPreservesORCPTWithoutNOTIFY(t *testing.T) {
	const recipient = "new@example.test"
	const original = "old@example.test"
	if got := recipientCommand(recipient, true, false, "", original); got != "RCPT TO:<new@example.test> ORCPT=rfc822;old@example.test" {
		t.Fatalf("ORCPT-only DSN option lost: %q", got)
	}
	if got := recipientCommand(recipient, false, false, "", original); got != "RCPT TO:<new@example.test>" {
		t.Fatalf("DSN option sent without DSN advertisement: %q", got)
	}
	if got := recipientCommand(recipient, true, false, "FAILURE"); got != "RCPT TO:<new@example.test> NOTIFY=FAILURE ORCPT=rfc822;new@example.test" {
		t.Fatalf("existing NOTIFY behavior changed: %q", got)
	}
}

func TestOutboundMissingMessageExtensionsArePermanent(t *testing.T) {
	for _, tc := range []struct {
		name, from, to, message string
		utf8, eightBit          bool
		wantSentinel            error
	}{
		{"SMTPUTF8 address", "josé@example.test", "to@example.test", "Subject: plain\r\n\r\nbody", false, true, errMissingSMTPUTF8},
		{"SMTPUTF8 header", "from@example.test", "to@example.test", "Subject: café\r\n\r\nbody", false, true, errMissingSMTPUTF8},
		{"8BITMIME body", "from@example.test", "to@example.test", "Subject: plain\r\n\r\ncafé", false, false, errMissing8BITMIME},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := outboundFormatRequirements(tc.from, tc.to, []byte(tc.message), tc.utf8, tc.eightBit, "mx.example.test")
			if !errors.Is(err, tc.wantSentinel) || !strings.HasPrefix(err.Error(), "554 ") {
				t.Fatalf("expected permanent %v, got %v", tc.wantSentinel, err)
			}
		})
	}
}

func TestPreferredMXFailureDoesNotHideRetryableFailure(t *testing.T) {
	_, _, extensionErr := outboundFormatRequirements("from@example.test", "to@example.test", []byte("Subject: plain\r\n\r\ncafé"), false, false, "mx.example.test")
	temporaryErr := errors.New("connection timed out")
	if got := preferredMXFailure(temporaryErr, extensionErr); got != temporaryErr {
		t.Fatalf("later incompatible MX concealed temporary failure: %v", got)
	}
	if got := preferredMXFailure(extensionErr, temporaryErr); got != temporaryErr {
		t.Fatalf("later temporary MX failure was not selected: %v", got)
	}
	if got := preferredMXFailure(nil, extensionErr); !errors.Is(got, errMissing8BITMIME) {
		t.Fatalf("all-incompatible MX result lost permanent failure: %v", got)
	}
	transientReply := errors.New("RCPT TO rejected by mx1.example: 451 4.3.0 try later")
	permanentReply := errors.New("RCPT TO rejected by mx2.example: 550 5.1.1 unknown user")
	if got := preferredMXFailure(transientReply, permanentReply); got != transientReply {
		t.Fatalf("later 5xx concealed earlier 4xx: %v", got)
	}
	if got := preferredMXFailure(permanentReply, transientReply); got != transientReply {
		t.Fatalf("earlier 5xx concealed later 4xx: %v", got)
	}
	if got := preferredMXFailure(permanentReply, extensionErr); got != permanentReply {
		t.Fatalf("all-permanent MX outcome changed unexpectedly: %v", got)
	}
}

func TestReadReplyFramingAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name, wire, want string
		fail             bool
	}{
		{"single", "250 accepted\r\n", "250 accepted", false},
		{"code only", "250\r\n", "250", false},
		{"multiline code only final", "250-first\r\n250\r\n", "250-first\r\n250", false},
		{"multiline", "250-first\r\n250 second\r\n", "250-first\r\n250 second", false},
		{"bare code continuation", "250-\r\n250 done\r\n", "250-\r\n250 done", false},
		{"truncated", "250 accepted", "", true},
		{"continuation EOF", "250-first\r\n", "", true},
		{"bare LF", "250 accepted\n", "", true},
		{"bad code", "hello\r\n", "", true},
		{"mixed codes", "250-first\r\n550 second\r\n", "", true},
		{"oversized line", "250 " + strings.Repeat("x", 4096) + "\r\n", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(2 * time.Second))
			go func() {
				_, _ = server.Write([]byte(tc.wire))
				_ = server.Close()
			}()
			got, err := readReply(client)
			if (err != nil) != tc.fail || (!tc.fail && got != tc.want) {
				t.Fatalf("got %q, %v; want %q, fail=%v", got, err, tc.want, tc.fail)
			}
		})
	}
}

func TestOutboundOperationsRefreshDeadlines(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if err := client.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, len("NOOP\r\n"))
		_, err := server.Read(buf)
		if err == nil && string(buf) != "NOOP\r\n" {
			err = errors.New("unexpected command")
		}
		if err == nil {
			_, err = server.Write([]byte("250 OK\r\n"))
		}
		done <- err
	}()
	if err := sendCmdWithTimeout(client, "NOOP", time.Second); err != nil {
		t.Fatal(err)
	}
	if reply, err := readReplyWithTimeout(client, time.Second); err != nil || reply != "250 OK" {
		t.Fatalf("reply=%q err=%v", reply, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestOutboundDataWriterRefreshesWriteDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if err := client.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 4)
		_, err := server.Read(buf)
		if err == nil && string(buf) != "data" {
			err = errors.New("unexpected data")
		}
		done <- err
	}()
	if _, err := (smtpDeadlineWriter{conn: client, timeout: time.Second}).Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSMTPReplyCodeAcceptsMultilineRecipientSuccess(t *testing.T) {
	for _, reply := range []string{"250", "250 accepted", "250-first\r\n250 accepted", "251-forwarding\r\n251 done"} {
		code := smtpReplyCode(reply)
		if code != "250" && code != "251" {
			t.Fatalf("recipient success %q classified as %q", reply, code)
		}
	}
	for _, reply := range []string{"", "25", "450 unavailable", "550 unknown"} {
		if code := smtpReplyCode(reply); code == "250" || code == "251" {
			t.Fatalf("recipient failure %q classified as %q", reply, code)
		}
	}
}

func TestWriteSMTPDataDotTransparency(t *testing.T) {
	var out bytes.Buffer
	if err := writeSMTPData(&out, []byte("Subject: test\r\n\r\none\r\n.\r\n..two\r\nlast")); err != nil {
		t.Fatal(err)
	}
	want := "Subject: test\r\n\r\none\r\n..\r\n...two\r\nlast\r\n.\r\n"
	if out.String() != want {
		t.Fatalf("got %q want %q", out.String(), want)
	}
}

type shortSMTPWriter struct{ bytes.Buffer }

func (w *shortSMTPWriter) Write(data []byte) (int, error) {
	if len(data) > 1 {
		data = data[:1]
	}
	return w.Buffer.Write(data)
}

func TestWriteSMTPDataHandlesShortWrites(t *testing.T) {
	w := &shortSMTPWriter{}
	if err := writeSMTPData(w, []byte("Subject: test\r\n\r\n.line")); err != nil {
		t.Fatal(err)
	}
	if got, want := w.String(), "Subject: test\r\n\r\n..line\r\n.\r\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestOutboundLostFinalReplyIsUncertain(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		write := func(s string) error { _, err := conn.Write([]byte(s)); return err }
		if err := write("220 mx.example.test ESMTP\r\n"); err != nil {
			done <- err
			return
		}
		for i, prefix := range []string{"EHLO ", "MAIL FROM:", "RCPT TO:", "DATA"} {
			line, err := r.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			if !strings.HasPrefix(line, prefix) {
				done <- errors.New("unexpected SMTP command: " + line)
				return
			}
			reply := "250 ok\r\n"
			if i == 0 {
				reply = "250 mx.example.test\r\n"
			}
			if i == 3 {
				reply = "354 continue\r\n"
			}
			if err := write(reply); err != nil {
				done <- err
				return
			}
		}
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			if line == ".\r\n" {
				break
			}
		}
		// Simulate a peer that accepted DATA but lost its final reply.
		done <- nil
	}()
	err = deliverToHostAt(listener.Addr().String(), "mx.example.test", "sender@example.test", "recipient@example.test", []byte("From: sender@example.test\r\nTo: recipient@example.test\r\n\r\nhello\r\n"), "mail.example.test", nil, false, "", "", "", "tcp", nil, "example.test", "disabled", nil)
	if !errors.Is(err, ErrDeliveryOutcomeUnknown) {
		t.Fatalf("expected uncertain outcome, got %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestWriteSMTPDataPreservesCanonicalEightBitBytes(t *testing.T) {
	message := []byte("Subject: café\r\n\r\nnaïve\r\n")
	var out bytes.Buffer
	if err := writeSMTPData(&out, message); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), append(append([]byte(nil), message...), []byte(".\r\n")...)) {
		t.Fatalf("SMTP DATA modified canonical message: %q", out.Bytes())
	}
}

func TestWriteSMTPDataRejectsOverlongWireLineBeforeWriting(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		fail bool
	}{
		{"maximum plain", strings.Repeat("a", 998), false},
		{"overlong plain", strings.Repeat("a", 999), true},
		{"maximum dot-stuffed", "." + strings.Repeat("a", 997), false},
		{"overlong dot-stuffed", "." + strings.Repeat("a", 998), true},
		{"bare CR", "one\rtwo", true},
		{"bare LF", "one\ntwo", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			err := writeSMTPData(&output, []byte("Subject: test\r\n\r\n"+tc.line+"\r\n"))
			if (err != nil) != tc.fail {
				t.Fatalf("err=%v, want fail=%v", err, tc.fail)
			}
			if tc.fail && output.Len() != 0 {
				t.Fatal("wrote partial DATA before rejecting long line")
			}
		})
	}
}

func TestEHLOCapabilitiesAreWholeCaseInsensitiveKeywordLines(t *testing.T) {
	caps := ehloCapabilities("250-mx.example says DSN STARTTLS\r\n250-8bitmime\r\n250-sMtPuTf8 extra\r\n250 SIZE 100000\r\n")
	if caps["DSN"] || caps["STARTTLS"] || !caps["8BITMIME"] || !caps["SMTPUTF8"] || !caps["SIZE"] {
		t.Fatalf("bad EHLO capability set: %+v", caps)
	}
	if ehloCapabilities("250 mx.example DSN\r\n")["DSN"] {
		t.Fatal("greeting text was treated as an extension")
	}
}

func TestOutboundFallsBackToHELOOnlyWhenEHLOUnknown(t *testing.T) {
	for _, tc := range []struct {
		reply       string
		wantHELO    bool
		wantFailure bool
	}{
		{"500 command not recognized\r\n", true, false},
		{"502 command not implemented\r\n", true, false},
		{"550 policy rejected\r\n", false, true},
	} {
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer server.Close()
			reader := bufio.NewReader(server)
			line, _ := reader.ReadString('\n')
			if line != "EHLO mail.example.test\r\n" {
				t.Errorf("first command=%q", line)
				return
			}
			_, _ = server.Write([]byte(tc.reply))
			if tc.wantHELO {
				line, _ = reader.ReadString('\n')
				if line != "HELO mail.example.test\r\n" {
					t.Errorf("fallback command=%q", line)
					return
				}
				_, _ = server.Write([]byte("250 mail.example.test\r\n"))
			}
		}()
		capabilities, err := smtpGreetingCapabilities(client, "mail.example.test")
		client.Close()
		<-done
		if (err != nil) != tc.wantFailure {
			t.Errorf("reply=%q error=%v", tc.reply, err)
		}
		if err == nil && len(capabilities) != 0 {
			t.Errorf("HELO fallback invented extensions: %+v", capabilities)
		}
	}
}

func TestOriginalRecipientParameterUsesUTF8Type(t *testing.T) {
	if got := originalRecipientParameter("alice@example.test", false); got != "rfc822;alice@example.test" {
		t.Fatalf("ASCII ORCPT=%q", got)
	}
	if got := originalRecipientParameter("josé+tag@example.test", true); got != "utf-8;josé\\x{2B}tag@example.test" {
		t.Fatalf("UTF-8 ORCPT=%q", got)
	}
	if got := originalRecipientParameter("josé+tag@example.test", false); got != "utf-8;jos\\x{E9}\\x{2B}tag@example.test" {
		t.Fatalf("legacy UTF-8 ORCPT=%q", got)
	}
}

func TestOutboundRejectsEnvelopeCommandInjection(t *testing.T) {
	for _, recipient := range []string{"victim@example.net\r\nDATA", "victim@example.net\nRCPT TO:<other@example.net>", "bad<addr@example.net"} {
		if err := SendMail("sender@example.com", recipient, []byte("Subject: test\r\n\r\nbody"), "mail.example.com", nil, false, "", "", "", "tcp", nil); err == nil || err.Error() != "invalid envelope address" {
			t.Fatalf("recipient %q was not rejected before networking: %v", recipient, err)
		}
	}
}

func TestOutboundPolicyLookupFailurePrecedesDNSAndNetwork(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	err = SendMail("alice@example.test", "bob@remote.test", []byte("Subject: test\r\n\r\nbody"), "mail.example.test", nil, false, "", "", "", "tcp", db)
	if err == nil || !strings.Contains(err.Error(), "loading sender transport policy") {
		t.Fatalf("policy lookup did not fail closed: %v", err)
	}
}

func TestDMARCPolicyCannotBeBypassedByMessageMetadata(t *testing.T) {
	if !shouldQuarantineDMARC(auth.DMARCFail, auth.PolicyReject) || !shouldQuarantineDMARC(auth.DMARCFail, auth.PolicyQuarantine) {
		t.Fatal("failed DMARC enforcement policy was bypassed")
	}
	if shouldQuarantineDMARC(auth.DMARCPass, auth.PolicyReject) || shouldQuarantineDMARC(auth.DMARCFail, auth.PolicyNone) {
		t.Fatal("DMARC routing quarantined a non-enforced result")
	}
}

func TestTLSReportEventsDescribeAppliedPolicies(t *testing.T) {
	sts := &mta_sts.Policy{Version: "STSv1", Mode: "enforce", MXHosts: []string{"*.example.net"}, MaxAge: 86400}
	dane := dns.TLSAResult{Authenticated: true, Records: []dns.TLSARecord{{Usage: 3, Selector: 1, MatchingType: 1, CertData: "aabb"}}}
	events := tlsReportEvents("example.net", "mx.example.net.", nil, sts, dane)
	if len(events) != 2 {
		t.Fatalf("got %d events, want STS and TLSA", len(events))
	}
	if events[0].PolicyType != "sts" || events[0].PolicyString[2] != "mx: *.example.net" {
		t.Fatalf("bad STS event: %+v", events[0])
	}
	if events[1].PolicyType != "tlsa" || events[1].PolicyString[0] != "3 1 1 aabb" || events[1].PolicyDomain != "mx.example.net" {
		t.Fatalf("bad TLSA event: %+v", events[1])
	}

	plain := tlsReportEvents("example.net", "mx.example.net", nil, nil, dns.TLSAResult{})
	if len(plain) != 1 || plain[0].PolicyType != "no-policy-found" {
		t.Fatalf("bad no-policy event: %+v", plain)
	}
}

func TestDANERequiredAlwaysRequiresTLS(t *testing.T) {
	if !transportTLSRequired(false, "required") {
		t.Fatal("required DANE must prohibit plaintext fallback")
	}
	if transportTLSRequired(false, "optional") {
		t.Fatal("optional DANE unexpectedly forced TLS without another TLS policy")
	}
	if !transportTLSRequired(true, "disabled") {
		t.Fatal("explicit TLS requirement was ignored")
	}
}

func TestSMTPUTF8Requirement(t *testing.T) {
	if requiresSMTPUTF8("a@example", "b@example", []byte("Subject: ascii\r\n\r\ncafé")) {
		t.Fatal("UTF-8 body alone incorrectly requires SMTPUTF8")
	}
	if !requiresSMTPUTF8("a@example", "b@example", []byte("Subject: café\r\n\r\nbody")) {
		t.Fatal("UTF-8 header did not require SMTPUTF8")
	}
}

func TestMatchSTSMX(t *testing.T) {
	tests := []struct {
		host, pattern string
		want          bool
	}{{"mx.example.com", "mx.example.com", true}, {"a.example.com", "*.example.com", true}, {"a.b.example.com", "*.example.com", false}, {"example.com", "*.example.com", false}}
	for _, tc := range tests {
		if got := matchSTSMX(tc.host, tc.pattern); got != tc.want {
			t.Errorf("matchSTSMX(%q,%q)=%v", tc.host, tc.pattern, got)
		}
	}
}
