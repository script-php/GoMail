package security

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

func TestReadLineLimited(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		limit       int
		wantErr     error
	}{
		{"short", "NOOP\r\n", 6, nil},
		{"too long", strings.Repeat("x", 10000) + "\n", 1000, ErrLineTooLong},
		{"unterminated", strings.Repeat("x", 10000), 1000, ErrLineTooLong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, err := ReadLineLimited(bufio.NewReaderSize(strings.NewReader(tc.input), 32), tc.limit)
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && line != tc.input) {
				t.Fatalf("line=%q err=%v", line, err)
			}
		})
	}
}

func TestParseCRLFCommandLine(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
		valid bool
	}{
		{"HELO example.test\r\n", "HELO example.test", true},
		{"HELO example.test\n", "", false},
		{"HELO example.test\r\r\n", "", false},
		{"MAIL FROM:<a@example.test>\rX: injected\r\n", "", false},
	} {
		got, err := ParseCRLFCommandLine(tc.input)
		if (err == nil) != tc.valid || got != tc.want {
			t.Errorf("parse %q = %q, %v", tc.input, got, err)
		}
	}
}
