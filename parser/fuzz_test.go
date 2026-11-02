package parser

import "testing"

func FuzzParseMessage(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("From: a@example.test\r\nTo: b@example.test\r\nSubject: hello\r\n\r\nbody"),
		[]byte("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nbody\r\n--x--\r\n"),
		[]byte("Content-Type: text/html; charset=utf-8\r\n\r\n<p>hello</p>"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		_, _ = Parse(raw)
	})
}

func FuzzParseDSN(f *testing.F) {
	for _, seed := range []string{
		"Final-Recipient: rfc822; user@example.test\r\nAction: failed\r\nStatus: 5.1.1\r\n",
		"Content-Type: multipart/report; boundary=x\r\n\r\n--x\r\nContent-Type: message/delivery-status\r\n\r\nFinal-Recipient: rfc822; a@b.test\r\nAction: delayed\r\nStatus: 4.2.0\r\n--x--\r\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		_, _ = ParseDSN(raw)
	})
}
