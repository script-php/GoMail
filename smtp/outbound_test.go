package smtp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
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

func TestMXDeliveryFailureWhenSTSPolicyRejectsAllHosts(t *testing.T) {
	err := mxDeliveryFailure("example.test", nil, true)
	if err == nil || !strings.Contains(err.Error(), "MTA-STS policy") {
		t.Fatalf("missing MTA-STS rejection reason: %v", err)
	}
	if code := SMTPFailureCode(err); code != 0 {
		t.Fatalf("policy rejection must remain retryable, got SMTP code %d", code)
	}
}

func TestRequiredSTARTTLSRejectionIsRetryable(t *testing.T) {
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
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		if _, err := conn.Write([]byte("220 mx.example.test ESMTP\r\n")); err != nil {
			done <- err
			return
		}
		for _, step := range []struct{ prefix, reply string }{
			{"EHLO ", "250-mx.example.test\r\n250 STARTTLS\r\n"},
			{"STARTTLS\r\n", "550 TLS temporarily unavailable\r\n"},
		} {
			line, err := reader.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			if !strings.HasPrefix(line, step.prefix) {
				done <- errors.New("unexpected SMTP command: " + line)
				return
			}
			if _, err := conn.Write([]byte(step.reply)); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	err = deliverToHostAt(listener.Addr().String(), "mx.example.test", "sender@example.test", "recipient@example.test", []byte("Subject: test\r\n\r\nbody\r\n"), "mail.example.test", &tls.Config{}, true, "", "", "", "tcp", nil, "example.test", "disabled", &mta_sts.Policy{Version: "STSv1", Mode: "enforce", MXHosts: []string{"mx.example.test"}, MaxAge: 3600})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS was rejected") {
		t.Fatalf("expected STARTTLS policy failure, got %v", err)
	}
	if code := SMTPFailureCode(err); code != 0 {
		t.Fatalf("remote STARTTLS 5xx was treated as permanent SMTP failure: %d", code)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestOutboundDeclaresExactSIZEWhenAdvertised(t *testing.T) {
	for _, raw := range []string{
		"Subject: size\r\n\r\nbody",
		"Subject: size\r\n\r\nbody\r\n",
	} {
		t.Run(fmt.Sprintf("trailing-crlf-%v", strings.HasSuffix(raw, "\r\n")), func(t *testing.T) {
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
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(conn)
				_, _ = conn.Write([]byte("220 mx.example.test ESMTP\r\n"))
				steps := []struct{ want, reply string }{
					{"EHLO mail.example.test\r\n", "250-mx.example.test\r\n250 SIZE 1000000\r\n"},
					{fmt.Sprintf("MAIL FROM:<sender@example.test> SIZE=%d\r\n", smtpDataSize([]byte(raw))), "250 sender accepted\r\n"},
					{"RCPT TO:<recipient@example.test>\r\n", "250 recipient accepted\r\n"},
					{"DATA\r\n", "354 continue\r\n"},
				}
				for _, step := range steps {
					line, err := reader.ReadString('\n')
					if err != nil || line != step.want {
						done <- fmt.Errorf("command %q (%v), want %q", line, err, step.want)
						return
					}
					if _, err := conn.Write([]byte(step.reply)); err != nil {
						done <- err
						return
					}
				}
				var transmitted strings.Builder
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						done <- err
						return
					}
					if line == ".\r\n" {
						break
					}
					transmitted.WriteString(line)
				}
				want := raw
				if !strings.HasSuffix(want, "\r\n") {
					want += "\r\n"
				}
				if got := transmitted.String(); got != want {
					done <- fmt.Errorf("DATA body %q, want %q", got, want)
					return
				}
				_, err = conn.Write([]byte("250 queued\r\n"))
				done <- err
			}()
			err = deliverToHostAt(listener.Addr().String(), "mx.example.test", "sender@example.test", "recipient@example.test", []byte(raw), "mail.example.test", nil, false, "", "", "", "tcp", nil, "example.test", "disabled", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSTSTestingMXMismatchIsReportedEvenWhenDeliverySucceeds(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "mail.db"), filepath.Join(t.TempDir(), "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
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
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		if _, err := conn.Write([]byte("220 mx.example.test ESMTP\r\n")); err != nil {
			done <- err
			return
		}
		for _, step := range []struct{ prefix, reply string }{
			{"EHLO ", "250 mx.example.test\r\n"},
			{"MAIL FROM:", "250 ok\r\n"},
			{"RCPT TO:", "250 ok\r\n"},
			{"DATA\r\n", "354 continue\r\n"},
		} {
			line, err := reader.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			if !strings.HasPrefix(line, step.prefix) {
				done <- errors.New("unexpected SMTP command: " + line)
				return
			}
			if _, err := conn.Write([]byte(step.reply)); err != nil {
				done <- err
				return
			}
		}
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			if line == ".\r\n" {
				break
			}
		}
		_, err = conn.Write([]byte("250 queued\r\n"))
		done <- err
	}()
	policy := &mta_sts.Policy{Version: "STSv1", Mode: "testing", MXHosts: []string{"allowed.example.test"}, MaxAge: 3600}
	err = deliverToHostAt(listener.Addr().String(), "mx.example.test", "sender@example.test", "recipient@example.test", []byte("Subject: test\r\n\r\nbody\r\n"), "mail.example.test", nil, false, "", "", "", "tcp", db, "example.test", "disabled", policy)
	if err != nil {
		t.Fatalf("testing-mode delivery failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	events, err := db.GetTLSFailuresForReport("example.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Successful || events[0].PolicyType != "sts" || events[0].FailureReason != "validation-failure" {
		t.Fatalf("wrong TLS-RPT outcome for testing-mode MX mismatch: %+v", events)
	}
}

func TestSMTPEnvelopeDomainAllowsQuotedAtInLocalPart(t *testing.T) {
	for _, tc := range []struct{ address, want string }{
		{`"sales@east"@example.net`, "example.net"},
		{"user@example.net", "example.net"},
		{"user@", ""},
		{"user", ""},
	} {
		if got := smtpEnvelopeDomain(tc.address); got != tc.want {
			t.Fatalf("domain of %q = %q, want %q", tc.address, got, tc.want)
		}
	}
}

func TestOutboundDNSDomainIDNA(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"BÜCHER.example", "xn--bcher-kva.example"},
		{"EXAMPLE.TEST", "example.test"},
	} {
		got, err := outboundDNSDomain(tc.input)
		if err != nil || got != tc.want {
			t.Fatalf("domain %q = %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
	for _, domain := range []string{"", ".example", "example.", "bad domain", "\xff"} {
		if got, err := outboundDNSDomain(domain); err == nil {
			t.Fatalf("domain %q unexpectedly accepted as %q", domain, got)
		}
	}
}

func TestASCIIEnvelopeDomainPreservesLocalPart(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{`"sales@east"@bücher.example`, `"sales@east"@xn--bcher-kva.example`},
		{"josé@bücher.example", "josé@xn--bcher-kva.example"},
		{"user@example.test", "user@example.test"},
		{"", ""},
	} {
		got, err := asciiEnvelopeDomain(tc.input)
		if err != nil || got != tc.want {
			t.Fatalf("envelope %q = %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
	address, err := asciiEnvelopeDomain("user@bücher.example")
	if err != nil {
		t.Fatal(err)
	}
	if utf8, eightBit, err := outboundFormatRequirements("sender@example.test", address, []byte("Subject: plain\r\n\r\nbody"), false, false, "mx.example.test"); err != nil || utf8 || eightBit {
		t.Fatalf("ASCII local part with IDNA domain needs no SMTPUTF8: %v %v %v", utf8, eightBit, err)
	}
	address, err = asciiEnvelopeDomain("josé@bücher.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := outboundFormatRequirements("sender@example.test", address, []byte("Subject: plain\r\n\r\nbody"), false, true, "mx.example.test"); !errors.Is(err, errMissingSMTPUTF8) {
		t.Fatalf("UTF-8 local part no longer requires SMTPUTF8: %v", err)
	}
}

func TestOutboundIDNDomainUsesALabelWithLegacySMTP(t *testing.T) {
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
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		write := func(s string) error { _, err := conn.Write([]byte(s)); return err }
		if err := write("220 mx.example.test ESMTP\r\n"); err != nil {
			done <- err
			return
		}
		for _, step := range []struct{ want, reply string }{
			{"EHLO mail.example.test\r\n", "250-mx.example.test\r\n250 DSN\r\n"},
			{"MAIL FROM:<sender@example.test>\r\n", "250 ok\r\n"},
			{"RCPT TO:<user@xn--bcher-kva.example> NOTIFY=FAILURE ORCPT=utf-8;user@b\\x{FC}cher.example\r\n", "250 ok\r\n"},
			{"DATA\r\n", "354 continue\r\n"},
		} {
			got, err := r.ReadString('\n')
			if err != nil || got != step.want {
				done <- fmt.Errorf("SMTP command = %q, %v; want %q", got, err, step.want)
				return
			}
			if err := write(step.reply); err != nil {
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
		done <- write("250 accepted\r\n")
	}()
	err = deliverToHostAt(listener.Addr().String(), "mx.example.test", "sender@example.test", "user@bücher.example", []byte("Subject: test\r\n\r\nbody\r\n"), "mail.example.test", nil, false, "FAILURE", "", "", "tcp", nil, "xn--bcher-kva.example", "disabled", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestOutboundPreservesConfiguredTLSMinimum(t *testing.T) {
	for _, tc := range []struct{ configured, want uint16 }{
		{0, tls.VersionTLS12},
		{tls.VersionTLS10, tls.VersionTLS12},
		{tls.VersionTLS12, tls.VersionTLS12},
		{tls.VersionTLS13, tls.VersionTLS13},
	} {
		if got := outboundMinTLSVersion(tc.configured); got != tc.want {
			t.Fatalf("configured %#x became %#x, want %#x", tc.configured, got, tc.want)
		}
	}
}

func TestDANESNIUsesTLSABaseDomain(t *testing.T) {
	for _, tc := range []struct{ mx, owner, want string }{
		{"mx.example.test", "_25._tcp.canonical.example.test.", "canonical.example.test"},
		{"mx.example.test", "_25._tcp.mx.example.test.", "mx.example.test"},
		{"mx.example.test", "", "mx.example.test"},
	} {
		if got := tlsaBaseDomain(tc.mx, tc.owner); got != tc.want {
			t.Fatalf("MX %q TLSA %q: SNI %q, want %q", tc.mx, tc.owner, got, tc.want)
		}
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
		{"SMTPUTF8 requires 8BITMIME", "josé@example.test", "to@example.test", "Subject: plain\r\n\r\nbody", true, false, errMissing8BITMIME},
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

func TestOutboundSMTPUTF8Uses8BITMIMEForASCIIMessage(t *testing.T) {
	utf8, eightBit, err := outboundFormatRequirements("josé@example.test", "to@example.test", []byte("Subject: plain\r\n\r\nbody"), true, true, "mx.example.test")
	if err != nil || !utf8 || !eightBit {
		t.Fatalf("SMTPUTF8 envelope must use BODY=8BITMIME: utf8=%v eightBit=%v err=%v", utf8, eightBit, err)
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
	transientReply := &replyFailure{"RCPT TO rejected by mx1.example", "451 4.3.0 try later"}
	permanentReply := &replyFailure{"RCPT TO rejected by mx2.example", "550 5.1.1 unknown user"}
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

func TestSMTPFailureCodeIgnoresNonSMTPStatusNumbers(t *testing.T) {
	for _, message := range []string{"MTA-STS policy for example.test: policy endpoint returned HTTP 503", "TLS handshake failed: remote port 550", "DNS lookup failed: resolver 503"} {
		if code := SMTPFailureCode(errors.New(message)); code != 0 {
			t.Fatalf("non-SMTP error %q classified as %d", message, code)
		}
	}
	if code := SMTPFailureCode(&replyFailure{"RCPT TO rejected by mx.example", "550 5.1.1 unknown user"}); code != 550 {
		t.Fatalf("real SMTP failure code = %d", code)
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

func TestOutboundAcceptsRCPT252AndPositiveDATACompletion(t *testing.T) {
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
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		if _, err := conn.Write([]byte("220 mx.example.test ESMTP\r\n")); err != nil {
			done <- err
			return
		}
		for _, step := range []struct{ prefix, reply string }{
			{"EHLO ", "250 mx.example.test\r\n"},
			{"MAIL FROM:", "250 sender accepted\r\n"},
			{"RCPT TO:", "252 cannot verify, will accept\r\n"},
			{"DATA\r\n", "354 send mail\r\n"},
		} {
			line, err := reader.ReadString('\n')
			if err != nil || !strings.HasPrefix(line, step.prefix) {
				done <- fmt.Errorf("SMTP command %q: %w", line, err)
				return
			}
			if _, err := conn.Write([]byte(step.reply)); err != nil {
				done <- err
				return
			}
		}
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			if line == ".\r\n" {
				break
			}
		}
		_, err = conn.Write([]byte("251 accepted for onward delivery\r\n"))
		done <- err
	}()
	err = deliverToHostAt(listener.Addr().String(), "mx.example.test", "sender@example.test", "recipient@example.test", []byte("From: sender@example.test\r\nTo: recipient@example.test\r\n\r\nhello\r\n"), "mail.example.test", nil, false, "", "", "", "tcp", nil, "example.test", "disabled", nil)
	if err != nil {
		t.Fatalf("positive SMTP replies rejected: %v", err)
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

func TestOutboundGreetingRenegotiationDropsPreviousExtensions(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		reader := bufio.NewReader(server)
		for _, exchange := range []struct {
			command, reply string
		}{
			{"EHLO mail.example.test\r\n", "250-mx.example.test\r\n250-STARTTLS\r\n250 DSN\r\n"},
			{"EHLO mail.example.test\r\n", "500 EHLO unavailable\r\n"},
			{"HELO mail.example.test\r\n", "250 mx.example.test\r\n"},
		} {
			line, err := reader.ReadString('\n')
			if err != nil || line != exchange.command {
				t.Errorf("command=%q, err=%v; want %q", line, err, exchange.command)
				return
			}
			_, _ = server.Write([]byte(exchange.reply))
		}
	}()
	before, err := smtpGreetingCapabilities(client, "mail.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !before["STARTTLS"] || !before["DSN"] {
		t.Fatalf("initial extensions missing: %+v", before)
	}
	after, err := smtpGreetingCapabilities(client, "mail.example.test")
	client.Close()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 0 {
		t.Fatalf("pre-TLS extensions survived renegotiation: %+v", after)
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
	for _, recipient := range []string{"victim@example.net\r\nDATA", "victim@example.net\nRCPT TO:<other@example.net>", "bad<addr@example.net", "victim@example.net\x00", "victim@example.net\x7f"} {
		if err := SendMail("sender@example.com", recipient, []byte("Subject: test\r\n\r\nbody"), "mail.example.com", nil, false, "", "", "", "tcp", nil); !errors.Is(err, ErrInvalidEnvelopeAddress) || SMTPFailureCode(err) != 553 {
			t.Fatalf("recipient %q was not rejected before networking: %v", recipient, err)
		}
	}
}

func TestOutboundRejectsMalformedQueuedDSNOptionsBeforeNetworking(t *testing.T) {
	for _, tc := range []struct{ notify, ret string }{
		{"SUCCESS\r\nDATA", ""},
		{"FAILURE,NEVER", ""},
		{"SUCCESS,SUCCESS", ""},
		{"", "FULL\r\nRCPT TO:<victim@example.net>"},
		{"", "UNKNOWN"},
	} {
		err := SendMail("sender@example.test", "recipient@example.test", []byte("Subject: test\r\n\r\nbody\r\n"), "mail.example.test", nil, false, tc.notify, tc.ret, "", "tcp", nil)
		if !errors.Is(err, errInvalidQueuedMessage) || SMTPFailureCode(err) != 554 {
			t.Fatalf("DSN options notify=%q ret=%q were not rejected: %v", tc.notify, tc.ret, err)
		}
	}
	for _, tc := range []struct{ notify, ret string }{
		{"", ""}, {"NEVER", "FULL"}, {"SUCCESS,FAILURE,DELAY", "HDRS"},
	} {
		if err := ValidateOutboundDSNOptions(tc.notify, tc.ret); err != nil {
			t.Fatalf("valid DSN options rejected: %+v: %v", tc, err)
		}
	}
}

func TestOutboundMissingRecipientDomainIsPermanent(t *testing.T) {
	err := SendMail("sender@example.test", "recipient@", []byte("Subject: test\r\n\r\nbody"), "mail.example.test", nil, false, "", "", "", "tcp", nil)
	if !errors.Is(err, ErrInvalidEnvelopeAddress) || SMTPFailureCode(err) != 553 {
		t.Fatalf("malformed recipient error = %v, code = %d; want permanent 553", err, SMTPFailureCode(err))
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
	canonical := dane
	canonical.Name = "_25._tcp.canonical.example.net."
	canonicalEvents := tlsReportEvents("example.net", "mx.example.net", nil, nil, canonical)
	if len(canonicalEvents) != 1 || canonicalEvents[0].PolicyDomain != "canonical.example.net" || canonicalEvents[0].ReceivingMXHostname != "mx.example.net" {
		t.Fatalf("TLSA policy domain did not follow authenticated base name: %+v", canonicalEvents)
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

func TestSMTPUTF8NestedMIMEHeaders(t *testing.T) {
	tests := []struct {
		name, message string
		want          bool
	}{
		{"multipart header", "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\nContent-Description: café\r\n\r\nhello\r\n--x--\r\n", true},
		{"attached message header", "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: message/rfc822\r\n\r\nFrom: alice@example.test\r\nSubject: café\r\n\r\nhello\r\n--x--\r\n", true},
		{"eight bit body", "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain; charset=utf-8\r\n\r\ncafé\r\n--x--\r\n", false},
		{"encoded attached message", "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\nU3ViamVjdDogY2Fmw6kNCg0KaGVsbG8=\r\n--x--\r\n", false},
		{"quoted-printable attached message", "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nSubject: caf=C3=A9\r\n\r\nhello\r\n--x--\r\n", false},
		{"malformed part header", "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\nMalformed café\r\n\r\nhello\r\n--x--\r\n", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := []byte(tc.message)
			if got := requiresSMTPUTF8("a@example.test", "b@example.test", msg); got != tc.want {
				t.Fatalf("requiresSMTPUTF8 = %v, want %v", got, tc.want)
			}
			_, _, err := outboundFormatRequirements("a@example.test", "b@example.test", msg, false, true, "mx.example.test")
			if tc.want && !errors.Is(err, errMissingSMTPUTF8) || !tc.want && err != nil {
				t.Fatalf("transport capability error = %v, want SMTPUTF8 required = %v", err, tc.want)
			}
		})
	}
}

func TestSMTPUTF8LargeMultipartStreamsPastFormerInspectionLimit(t *testing.T) {
	prefix := "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\n"
	largeBody := strings.Repeat("a", 33<<20)
	message := []byte(prefix + largeBody + "\r\n--x--\r\n")
	if requiresSMTPUTF8("a@example.test", "b@example.test", message) {
		t.Fatal("large ASCII multipart message incorrectly requires SMTPUTF8")
	}
	message = []byte(prefix + largeBody + "\r\n--x\r\nContent-Description: café\r\n\r\nbody\r\n--x--\r\n")
	if !requiresSMTPUTF8("a@example.test", "b@example.test", message) {
		t.Fatal("UTF-8 header after large ASCII part was missed")
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

func TestOutboundCommandRejectsEmbeddedTerminators(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	for _, command := range []string{
		"EHLO mail.example\r\nMAIL FROM:<attacker@example>",
		"RCPT TO:<user@example>\nDATA",
		"MAIL FROM:<sender@example>\x00",
	} {
		if err := sendCmdWithTimeout(client, command, time.Second); err == nil {
			t.Fatalf("accepted command with an embedded control: %q", command)
		}
	}
	if err := peer.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if n, err := peer.Read(one[:]); n != 0 || err == nil {
		t.Fatalf("rejected command wrote to peer: n=%d err=%v", n, err)
	}
}

func TestOutboundDSNMetadataRejectedBeforeDNS(t *testing.T) {
	message := []byte("From: sender@example.test\r\n\r\nbody\r\n")
	for _, tc := range []struct{ name, envID, original string }{
		{"oversized ENVID", strings.Repeat("x", 101), "recipient@example.test"},
		{"encoded ENVID overflow", strings.Repeat(" ", 40), "recipient@example.test"},
		{"control in ENVID", "ok\r\nforged", "recipient@example.test"},
		{"control in ORCPT", "valid", "recipient@example.test\r\nforged"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := sendMail("sender@example.test", "recipient@example.test", message, "mail.example.test", nil, false, "FAILURE", "HDRS", tc.envID, "tcp", nil, false, "", tc.original)
			if !errors.Is(err, errInvalidQueuedMessage) {
				t.Fatalf("invalid metadata reached DNS or transport: %v", err)
			}
		})
	}
}
