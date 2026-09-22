package dns

import (
	"strings"
	"testing"
)

func TestParseTLSARecordValidation(t *testing.T) {
	valid256 := strings.Repeat("ab", 32)
	valid512 := strings.Repeat("cd", 64)
	tests := []struct{name, input string; ok bool}{
		{"sha256", "3 1 1 " + valid256, true},
		{"sha512 split hex", "2 0 2 " + valid512[:64] + " " + valid512[64:], true},
		{"exact", "3 0 0 00ff", true},
		{"usage", "4 1 1 " + valid256, false},
		{"selector", "3 2 1 " + valid256, false},
		{"matching", "3 1 3 " + valid256, false},
		{"odd hex", "3 1 0 abc", false},
		{"non hex", "3 1 0 nope", false},
		{"empty", "3 1 0", false},
		{"wrong sha256 length", "3 1 1 ab", false},
		{"wrong sha512 length", "3 1 2 ab", false},
	}
	for _, tc := range tests { t.Run(tc.name, func(t *testing.T) { _, err := ParseTLSARecord(tc.input); if (err == nil) != tc.ok { t.Fatalf("ok=%v err=%v", tc.ok, err) } }) }
}
