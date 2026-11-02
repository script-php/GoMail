package smtp

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestOutboundOpportunisticTLSAcceptsSelfSignedPeer(t *testing.T) {
	runOutboundSTARTTLSTest(t, 0, 0, true)
}

func TestOutboundRespectsTLS13Minimum(t *testing.T) {
	runOutboundSTARTTLSTest(t, tls.VersionTLS13, tls.VersionTLS12, false)
}

func runOutboundSTARTTLSTest(t *testing.T, clientMin, serverMax uint16, wantDelivery bool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mx.example.test"}, DNSNames: []string{"mx.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
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
		read := bufio.NewReader(conn)
		write := func(s string) error { _, err := conn.Write([]byte(s)); return err }
		if err := write("220 mx.example.test ESMTP\r\n"); err != nil {
			done <- err
			return
		}
		if line, err := read.ReadString('\n'); err != nil || !strings.HasPrefix(line, "EHLO ") {
			done <- fmt.Errorf("expected EHLO, got %q: %v", line, err)
			return
		}
		if err := write("250-mx.example.test\r\n250 STARTTLS\r\n"); err != nil {
			done <- err
			return
		}
		if line, err := read.ReadString('\n'); err != nil || line != "STARTTLS\r\n" {
			done <- fmt.Errorf("expected STARTTLS, got %q: %v", line, err)
			return
		}
		if err := write("220 ready\r\n"); err != nil {
			done <- err
			return
		}
		secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: serverMax})
		if err := secure.Handshake(); err != nil {
			if wantDelivery {
				done <- err
			} else {
				done <- nil
			}
			return
		}
		read = bufio.NewReader(secure)
		write = func(s string) error { _, err := secure.Write([]byte(s)); return err }
		for i, prefix := range []string{"EHLO ", "MAIL FROM:", "RCPT TO:", "DATA"} {
			line, err := read.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			if !strings.HasPrefix(line, prefix) {
				done <- fmt.Errorf("expected %q, got %q", prefix, line)
				return
			}
			reply := "250 ok\r\n"
			if i == 3 {
				reply = "354 continue\r\n"
			}
			if err := write(reply); err != nil {
				done <- err
				return
			}
		}
		for {
			line, err := read.ReadString('\n')
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
	message := []byte("From: sender@example.test\r\nTo: recipient@example.test\r\n\r\nhello\r\n")
	err = deliverToHostAt(listener.Addr().String(), "mx.example.test", "sender@example.test", "recipient@example.test", message, "mail.example.test", &tls.Config{MinVersion: clientMin}, false, "", "", "", "tcp", nil, "example.test", "disabled", nil)
	if (err == nil) != wantDelivery {
		t.Fatalf("delivery error = %v, want delivery = %v", err, wantDelivery)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
