package mailclient

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"gomail/config"
)

func TestSubmissionSTARTTLSDoesNotLeaveHandshakeWriteDeadline(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mail.example.test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mail.example.test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	s := &Server{cfg: &config.Config{Clients: config.MailClientsConfig{ReadTimeout: 1, WriteTimeout: 3}}, tlsConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}
	p := &submissionSession{server: s, conn: serverConn, reader: bufio.NewReader(serverConn), writer: bufio.NewWriter(serverConn), ehlo: true}
	done := make(chan bool, 1)
	go func() { done <- p.startTLS() }()
	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(clientConn).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "220 ") {
		t.Fatalf("STARTTLS response=%q err=%v", line, err)
	}
	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true}) // Test-only self-signed certificate.
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	if !<-done {
		t.Fatal("STARTTLS handshake failed")
	}
	time.Sleep(1200 * time.Millisecond)
	go p.reply(250, "still writable")
	_ = clientTLS.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err = bufio.NewReader(clientTLS).ReadString('\n')
	if err != nil || line != "250 still writable\r\n" {
		t.Fatalf("post-handshake reply=%q err=%v", line, err)
	}
}
