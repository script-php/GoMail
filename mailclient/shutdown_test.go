package mailclient

import (
	"net"
	"testing"
	"time"

	"gomail/config"
)

func TestStopClosesIdleAndContinuouslyActiveClients(t *testing.T) {
	server := NewServer(&config.Config{Clients: config.MailClientsConfig{MaxConnections: 4}}, nil, nil, nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.addListener(listener)
	server.acceptWG.Add(1)
	go server.acceptLoop(listener, "test", func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 32)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	})
	for i := 0; i < 2; i++ {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if i == 1 {
			go func() {
				for {
					if _, err := conn.Write([]byte("NOOP\r\n")); err != nil {
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
			}()
		}
	}
	deadline := time.Now().Add(time.Second)
	for {
		server.mu.Lock()
		count := len(server.connections)
		server.mu.Unlock()
		if count == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tracked %d clients, expected 2", count)
		}
		time.Sleep(5 * time.Millisecond)
	}
	started := time.Now()
	server.Stop()
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("shutdown took %s", elapsed)
	}
	server.Stop()
}
