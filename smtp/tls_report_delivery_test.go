package smtp

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTLSReportRetriesPlaintextOnFreshConnectionAfterSTARTTLSFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		for attempt := 0; attempt < 2; attempt++ {
			conn, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			r := bufio.NewReader(conn)
			_, _ = fmt.Fprint(conn, "220 mx.example.test ESMTP\r\n")
			line, err := r.ReadString('\n')
			if err != nil || !strings.HasPrefix(line, "EHLO ") {
				done <- fmt.Errorf("greeting %q: %v", line, err)
				conn.Close()
				return
			}
			_, _ = fmt.Fprint(conn, "250-mx.example.test\r\n250 STARTTLS\r\n")
			if attempt == 0 {
				line, err = r.ReadString('\n')
				if err != nil || line != "STARTTLS\r\n" {
					done <- fmt.Errorf("first attempt %q: %v", line, err)
					conn.Close()
					return
				}
				_, _ = fmt.Fprint(conn, "220 Go ahead\r\n")
				conn.Close() // TLS handshake fails after STARTTLS acceptance.
				continue
			}
			for _, step := range []struct{ prefix, reply string }{
				{"MAIL FROM:", "250 sender ok\r\n"},
				{"RCPT TO:", "250 recipient ok\r\n"},
				{"DATA\r\n", "354 send data\r\n"},
			} {
				line, err = r.ReadString('\n')
				if err != nil || !strings.HasPrefix(line, step.prefix) {
					done <- fmt.Errorf("plaintext attempt %q: %v", line, err)
					conn.Close()
					return
				}
				_, _ = fmt.Fprint(conn, step.reply)
			}
			for {
				line, err = r.ReadString('\n')
				if err != nil {
					done <- err
					conn.Close()
					return
				}
				if line == ".\r\n" {
					break
				}
			}
			_, _ = fmt.Fprint(conn, "250 accepted\r\n")
			line, err = r.ReadString('\n')
			if err == nil && line == "QUIT\r\n" {
				_, _ = fmt.Fprint(conn, "221 bye\r\n")
			}
			conn.Close()
			done <- nil
		}
	}()
	err = deliverTLSReportHostAt(listener.Addr().String(), "mx.example.test", "sender@example.test", "recipient@example.test", []byte("Subject: report\r\n\r\nbody\r\n"), "mail.example.test", &tls.Config{}, "", "", "", "tcp", "example.test", "recipient@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
