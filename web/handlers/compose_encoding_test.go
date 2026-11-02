package handlers

import (
	"io"
	"mime/quotedprintable"
	"strings"
	"testing"
)

func TestComposeTextBodyIsCanonicalAndLineLimited(t *testing.T) {
	body := "first\nsecond\rthird\r\nfourth café\n" + strings.Repeat("x", 2000)
	encoded := encodeComposeTextBody(body)
	if strings.Contains(strings.ReplaceAll(encoded, "\r\n", ""), "\n") || strings.Contains(strings.ReplaceAll(encoded, "\r\n", ""), "\r") {
		t.Fatal("encoded body contains a bare CR or LF")
	}
	for _, line := range strings.Split(encoded, "\r\n") {
		if len(line)+2 > 1000 {
			t.Fatalf("encoded SMTP line has %d octets", len(line)+2)
		}
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != normalizeBodyLineEndings(body) {
		t.Fatal("quoted-printable round trip changed composed text")
	}
}
