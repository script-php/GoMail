package web

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestShutdownDrainsActiveRequest(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := &Server{httpServer: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, "queued\n")
	})}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.httpServer.Serve(listener) }()
	responseDone := make(chan error, 1)
	go func() {
		response, err := http.Get("http://" + listener.Addr().String())
		if err != nil {
			responseDone <- err
			return
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err == nil && string(body) != "queued\n" {
			err = io.ErrUnexpectedEOF
		}
		responseDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request never entered handler")
	}
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- server.Shutdown() }()
	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown returned before active request completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-responseDone; err != nil {
		t.Fatalf("active request was interrupted: %v", err)
	}
	if err := <-shutdownDone; err != nil {
		t.Fatalf("graceful shutdown: %v", err)
	}
	if err := <-serveDone; err != http.ErrServerClosed {
		t.Fatalf("server exit: %v", err)
	}
}
