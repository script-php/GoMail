package handlers

import (
	"bytes"
	"strings"
	"testing"

	"gomail/store"
)

func TestForwardedRFC822BytesRejectsNoncanonicalSource(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"bare LF", []byte("From: a@example.test\n\nbody")},
		{"bare CR", []byte("From: a@example.test\r\n\r\nbody\r")},
		{"missing separator", []byte("From: a@example.test\r\n")},
		{"NUL", []byte("From: a@example.test\r\n\r\nbody\x00")},
		{"overlong line", []byte("From: a@example.test\r\n\r\n" + strings.Repeat("x", 999))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := forwardedRFC822Bytes(&store.Message{RawMessage: tc.raw}); err == nil {
				t.Fatal("noncanonical source was accepted")
			}
		})
	}
	raw := []byte("From: a@example.test\r\n\r\nbody\r\n")
	got, err := forwardedRFC822Bytes(&store.Message{RawMessage: raw})
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("canonical source changed: %q, %v", got, err)
	}
}
