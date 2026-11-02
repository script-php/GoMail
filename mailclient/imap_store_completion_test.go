package mailclient

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"gomail/config"
	"gomail/store"
)

func TestIMAPCommittedStoreCompletion(t *testing.T) {
	for _, tc := range []struct {
		modified []store.IMAPMessageRef
		want     string
	}{
		{want: "a1 OK STORE completed"},
		{modified: []store.IMAPMessageRef{{Sequence: 2, UID: 7}}, want: "a1 OK [MODIFIED 7] STORE completed"},
	} {
		server, client := net.Pipe()
		s := &imapSession{server: &Server{cfg: &config.Config{Clients: config.MailClientsConfig{WriteTimeout: 1}}}, conn: server, writer: bufio.NewWriter(server)}
		done := make(chan struct{})
		go func() { s.finishStore("a1", tc.modified, true); close(done) }()
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		line, err := bufio.NewReader(client).ReadString('\n')
		if err != nil || !strings.HasPrefix(line, tc.want) {
			t.Fatalf("completion=%q err=%v want %q", line, err, tc.want)
		}
		<-done
		_ = client.Close()
		_ = server.Close()
	}
}
