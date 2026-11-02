package smtp

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func TestGreetingControlsMailExtensions(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, writer: bufio.NewWriter(server), state: StateReady, maxSize: 1024, writeTimeout: time.Second}
	reader := bufio.NewReader(client)
	call := func(action func(), prefix string) {
		t.Helper()
		done := make(chan struct{})
		go func() { action(); close(done) }()
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, prefix) {
			t.Fatalf("reply=%q err=%v, want %s", line, err, prefix)
		}
		<-done
	}
	call(func() { s.handleMAIL("FROM:<alice@example.test>") }, "503 ")
	call(func() { s.handleHELO("remote.example.test") }, "250 ")
	call(func() { s.handleMAIL("FROM:<alice@example.test> BODY=8BITMIME") }, "555 ")
	call(func() { s.handleBDAT("0 LAST") }, "503 ")
	call(func() { s.handleMAIL("FROM:<alice@example.test>") }, "250 ")
	if s.state != StateMail {
		t.Fatal("legacy HELO mail transaction rejected")
	}
	done := make(chan struct{})
	go func() { s.handleEHLO("remote.example.test"); close(done) }()
	for {
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "250") {
			t.Fatalf("EHLO reply=%q err=%v", line, err)
		}
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	<-done
	call(func() { s.handleMAIL("FROM:<alice@example.test> BODY=8BITMIME") }, "250 ")
}

func TestOversizedBDATDrainsBeforeFailure(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, reader: bufio.NewReader(strings.NewReader("ABCDE")), writer: bufio.NewWriter(server), state: StateRcpt, esmtp: true, maxSize: 4, readTimeout: time.Second, writeTimeout: time.Second}
	done := make(chan struct{})
	go func() { s.handleBDAT("5 LAST"); close(done) }()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "552 ") {
		t.Fatalf("BDAT reply=%q err=%v", line, err)
	}
	<-done
	if s.state != StateData || !s.bdatFailed || s.data.Len() != 0 {
		t.Fatalf("failed BDAT state=%d failed=%v bytes=%d", s.state, s.bdatFailed, s.data.Len())
	}
	if buffered := s.reader.Buffered(); buffered != 0 {
		t.Fatalf("undrained BDAT bytes=%d", buffered)
	}
}
