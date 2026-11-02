package smtp

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNoArgumentCommandsRejectParametersWithoutChangingTransaction(t *testing.T) {
	for _, command := range []string{"DATA extra", "RSET extra", "QUIT extra", "STARTTLS extra"} {
		t.Run(command, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			s := &Session{
				conn: server, writer: bufio.NewWriter(server), state: StateRcpt,
				greeted: true, esmtp: true, mailFrom: "sender@example.test",
				rcptTo: []string{"recipient@example.test"}, writeTimeout: time.Second,
			}
			done := make(chan struct{})
			go func() { s.handleCommand(command); close(done) }()
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			reply, err := bufio.NewReader(client).ReadString('\n')
			if err != nil || !strings.HasPrefix(reply, "501 5.5.2 ") {
				t.Fatalf("reply=%q err=%v", reply, err)
			}
			<-done
			if s.state != StateRcpt || s.mailFrom != "sender@example.test" || len(s.rcptTo) != 1 {
				t.Fatalf("rejected command altered transaction: state=%d from=%q rcpt=%v", s.state, s.mailFrom, s.rcptTo)
			}
		})
	}
}
