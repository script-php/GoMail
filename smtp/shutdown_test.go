package smtp

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestInboundStopClosesActiveSessions(t *testing.T) {
	server := &InboundServer{quit: make(chan struct{}), connections: make(map[net.Conn]struct{})}
	var clients []net.Conn
	for i := 0; i < 2; i++ {
		side, client := net.Pipe()
		clients = append(clients, client)
		server.connections[side] = struct{}{}
		server.wg.Add(1)
		go func() {
			defer server.wg.Done()
			buf := make([]byte, 32)
			for {
				if _, err := side.Read(buf); err != nil {
					return
				}
			}
		}()
	}
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		for {
			if _, err := clients[1].Write([]byte("NOOP\r\n")); err != nil {
				return
			}
		}
	}()
	started := time.Now()
	server.Stop()
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("shutdown took %s", elapsed)
	}
	for _, client := range clients {
		_ = client.Close()
	}
	writers.Wait()
	server.Stop()
}
