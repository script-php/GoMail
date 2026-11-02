package mailclient

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"gomail/config"
)

func TestSubmissionRejectsArgumentsToNoArgumentCommands(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	s := &Server{cfg: &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test"}, Clients: config.MailClientsConfig{ReadTimeout: 1, WriteTimeout: 1}}}
	done := make(chan struct{})
	go func() { s.handleSubmission(server); close(done) }()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(client)
	if _, err := r.ReadString('\n'); err != nil { // greeting
		t.Fatal(err)
	}
	for _, command := range []string{"DATA extra", "RSET extra", "QUIT extra", "STARTTLS extra"} {
		if _, err := client.Write([]byte(command + "\r\n")); err != nil {
			t.Fatal(err)
		}
		response, err := r.ReadString('\n')
		if err != nil || !strings.HasPrefix(response, "501 ") {
			t.Fatalf("%s reply=%q err=%v", command, response, err)
		}
	}
	if _, err := client.Write([]byte("NOOP\r\n")); err != nil {
		t.Fatal(err)
	}
	response, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(response, "250 ") {
		t.Fatalf("connection unusable after rejected command: reply=%q err=%v", response, err)
	}
	_ = client.Close()
	<-done
}
