package smtp

import (
	"bytes"
	"testing"
)

func TestWriteSMTPDataDotTransparency(t *testing.T) {
	var out bytes.Buffer
	if err := writeSMTPData(&out, []byte("Subject: test\r\n\r\none\r\n.\r\n..two\r\nlast")); err != nil {
		t.Fatal(err)
	}
	want := "Subject: test\r\n\r\none\r\n..\r\n...two\r\nlast\r\n.\r\n"
	if out.String() != want {
		t.Fatalf("got %q want %q", out.String(), want)
	}
}
func TestSMTPUTF8Requirement(t *testing.T) {
	if requiresSMTPUTF8("a@example", "b@example", []byte("Subject: ascii\r\n\r\ncafé")) {
		t.Fatal("UTF-8 body alone incorrectly requires SMTPUTF8")
	}
	if !requiresSMTPUTF8("a@example", "b@example", []byte("Subject: café\r\n\r\nbody")) {
		t.Fatal("UTF-8 header did not require SMTPUTF8")
	}
}

func TestMatchSTSMX(t *testing.T) {
	tests := []struct {
		host, pattern string
		want          bool
	}{{"mx.example.com", "mx.example.com", true}, {"a.example.com", "*.example.com", true}, {"a.b.example.com", "*.example.com", false}, {"example.com", "*.example.com", false}}
	for _, tc := range tests {
		if got := matchSTSMX(tc.host, tc.pattern); got != tc.want {
			t.Errorf("matchSTSMX(%q,%q)=%v", tc.host, tc.pattern, got)
		}
	}
}
