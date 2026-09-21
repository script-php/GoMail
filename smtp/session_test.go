package smtp

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBDATRejectsOversizedChunkBeforeReading(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &Session{conn: server, reader: bufio.NewReader(server), writer: bufio.NewWriter(server), state: StateRcpt, maxSize: 1024, readTimeout: time.Second, writeTimeout: time.Second}
	done := make(chan struct{})
	go func() { s.handleBDAT("9223372036854775807 LAST"); close(done) }()
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(reply, "552") {
		t.Fatalf("unexpected reply: %s", reply)
	}
	<-done
	if s.state != StateQuit || s.data.Len() != 0 {
		t.Fatal("oversized chunk left session usable")
	}
}

func TestDataLineBoundedAcrossReaderBuffers(t *testing.T) {
	s := &Session{reader: bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 10000)+"\r\n"), 32)}
	line, err := s.readDataLine(10002)
	if err != nil || len(line) != 10002 {
		t.Fatalf("long bounded line: len=%d err=%v", len(line), err)
	}
	s.reader = bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 10000)), 32)
	if _, err := s.readDataLine(100); err == nil {
		t.Fatal("unbounded line accepted")
	}
}
