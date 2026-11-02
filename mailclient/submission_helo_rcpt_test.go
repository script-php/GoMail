package mailclient

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"gomail/config"
)

func TestSubmissionHELORejectsRCPTParameters(t *testing.T) {
	for _, parameter := range []string{"NOTIFY=SUCCESS", "ORCPT=rfc822;recipient@example.test"} {
		t.Run(parameter, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			p := &submissionSession{
				server: &Server{cfg: &config.Config{Clients: config.MailClientsConfig{WriteTimeout: 1}}},
				conn:   server, writer: bufio.NewWriter(server), greeted: true, ehlo: false,
				mailFrom: "sender@example.test",
			}
			done := make(chan struct{})
			go func() { p.handleRCPT("TO:<recipient@example.test> " + parameter); close(done) }()
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			reply, err := bufio.NewReader(client).ReadString('\n')
			if err != nil || !strings.HasPrefix(reply, "555 ") {
				t.Fatalf("reply=%q err=%v", reply, err)
			}
			<-done
			if len(p.recipients) != 0 || p.mailFrom != "sender@example.test" {
				t.Fatalf("rejected RCPT changed envelope: recipients=%v sender=%q", p.recipients, p.mailFrom)
			}
		})
	}
}
