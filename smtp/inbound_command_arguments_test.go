package smtp

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func TestInboundDATARejectsArgumentsBeforeTransfer(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	session := &Session{
		conn: server, reader: bufio.NewReader(server), writer: bufio.NewWriter(server),
		readTimeout: time.Second, writeTimeout: time.Second,
	}
	done := make(chan struct{})
	go func() { (&InboundServer{}).runSession(session); close(done) }()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(client)
	if _, err := r.ReadString('\n'); err != nil { // greeting
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("DATA extra\r\n")); err != nil {
		t.Fatal(err)
	}
	response, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(response, "501 5.5.2 ") {
		t.Fatalf("DATA reply=%q err=%v", response, err)
	}
	if session.state != StateReady || len(session.rcptTo) != 0 {
		t.Fatalf("rejected DATA changed transaction: state=%d rcpt=%v", session.state, session.rcptTo)
	}
	if _, err := client.Write([]byte("RSET\r\n")); err != nil {
		t.Fatal(err)
	}
	response, err = r.ReadString('\n')
	if err != nil || !strings.HasPrefix(response, "250 ") {
		t.Fatalf("RSET reply=%q err=%v", response, err)
	}
	_ = client.Close()
	<-done
}
