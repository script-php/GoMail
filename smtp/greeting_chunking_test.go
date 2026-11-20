package smtp

import (
	"bufio"
	"fmt"
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

func TestBDATStreamsExactChunksWithoutConsumingNextCommand(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, reader: bufio.NewReader(strings.NewReader("abcDEFGNOOP\r\n")), writer: bufio.NewWriter(server), state: StateRcpt, esmtp: true, maxSize: 7, readTimeout: time.Second, writeTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		s.handleBDAT("3")
		s.handleBDAT("4 LAST")
		close(done)
	}()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if line, err := bufio.NewReader(client).ReadString('\n'); err != nil || !strings.HasPrefix(line, "250 ") {
		t.Fatalf("first chunk reply=%q err=%v", line, err)
	}
	<-done
	if s.state != StateReady || s.data.String() != "abcDEFG" {
		t.Fatalf("BDAT state=%d data=%q", s.state, s.data.String())
	}
	if next, err := s.reader.ReadString('\n'); err != nil || next != "NOOP\r\n" {
		t.Fatalf("next command consumed by BDAT: %q err=%v", next, err)
	}
}

func TestFailedBDATDrainsPipelinedChunks(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, reader: bufio.NewReader(strings.NewReader("ABCDEWXYZNOOP\r\n")), writer: bufio.NewWriter(server), state: StateRcpt, esmtp: true, maxSize: 4, readTimeout: time.Second, writeTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		s.handleBDAT("5")
		s.handleBDAT("4 LAST")
		close(done)
	}()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	replies := bufio.NewReader(client)
	for _, prefix := range []string{"552 ", "503 "} {
		line, err := replies.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, prefix) {
			t.Fatalf("failed BDAT reply=%q err=%v, want %s", line, err, prefix)
		}
	}
	<-done
	if s.data.Len() != 0 || !s.bdatFailed {
		t.Fatalf("failed transaction retained data=%d state=%v", s.data.Len(), s.bdatFailed)
	}
	if next, err := s.reader.ReadString('\n'); err != nil || next != "NOOP\r\n" {
		t.Fatalf("pipelined BDAT bytes remain in command stream: %q err=%v", next, err)
	}
}

func TestRateLimitedBDATDrainsBeforeReply(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, reader: bufio.NewReader(strings.NewReader("ABCDNOOP\r\n")), writer: bufio.NewWriter(server), state: StateRcpt, esmtp: true, maxSize: 100, readTimeout: time.Second, writeTimeout: time.Second}
	done := make(chan struct{})
	go func() { s.rejectBDATChunkForRateLimit("4 LAST"); close(done) }()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if line, err := bufio.NewReader(client).ReadString('\n'); err != nil || !strings.HasPrefix(line, "451 ") {
		t.Fatalf("rate-limit reply=%q err=%v", line, err)
	}
	<-done
	if s.state != StateData || !s.bdatFailed || s.data.Len() != 0 {
		t.Fatalf("failed transaction state=%d failed=%v bytes=%d", s.state, s.bdatFailed, s.data.Len())
	}
	if next, err := s.reader.ReadString('\n'); err != nil || next != "NOOP\r\n" {
		t.Fatalf("rate-limited chunk leaked into command stream: %q err=%v", next, err)
	}
}

func TestBDATChunkSizeIsDigitsOnly(t *testing.T) {
	for _, value := range []string{"+3", "-3", "3x", ""} {
		if _, _, err := parseBDATArguments(value); err == nil {
			t.Fatalf("accepted invalid BDAT size %q", value)
		}
	}
	if size, last, err := parseBDATArguments("03 LAST"); err != nil || size != 3 || !last {
		t.Fatalf("valid BDAT size rejected: size=%d last=%v err=%v", size, last, err)
	}
}

func TestBDATOutsideTransactionGetsOneReply(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	sess := NewSession(server, "mx.example.test", nil, nil, nil, 1024, 10, time.Second, time.Second, "", false, nil)
	sess.esmtp = true
	sess.greeted = true
	done := make(chan struct{})
	go func() { (&InboundServer{}).runSession(sess); close(done) }()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	replies := bufio.NewReader(client)
	if line, err := replies.ReadString('\n'); err != nil || !strings.HasPrefix(line, "220 ") {
		t.Fatalf("greeting=%q err=%v", line, err)
	}
	for _, step := range []struct{ command, prefix string }{{"BDAT 4 LAST\r\nABCD", "503 "}, {"NOOP\r\n", "250 "}, {"QUIT\r\n", "221 "}} {
		if _, err := fmt.Fprint(client, step.command); err != nil {
			t.Fatal(err)
		}
		line, err := replies.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, step.prefix) {
			t.Fatalf("reply=%q err=%v, want %s", line, err, step.prefix)
		}
	}
	<-done
}
