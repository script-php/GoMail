package mailclient

import "testing"

func TestParseQRESYNCSelectOptions(t *testing.T) {
	condstore, request, err := parseSelectOptions([]string{"(", "QRESYNC", "(", "123", "456", "1:20", "(", "1:3", "10:12", ")", ")", ")"})
	if err != nil || !condstore || request == nil || request.uidValidity != 123 || request.modSeq != 456 || request.knownUIDs != "1:20" {
		t.Fatalf("parsed condstore=%v request=%#v err=%v", condstore, request, err)
	}
	for _, tokens := range [][]string{
		{"(", "QRESYNC", "(", "0", "1", ")", ")"},
		{"(", "QRESYNC", "(", "1", "bad", ")", ")"},
		{"(", "QRESYNC", "(", "1", "2", "0:4", ")", ")"},
		{"(", "QRESYNC", "(", "1", "2", "1:4", "(", "1", ")", ")", ")"},
	} {
		if _, _, err := parseSelectOptions(tokens); err == nil {
			t.Fatalf("accepted malformed QRESYNC options: %q", tokens)
		}
	}
}

func TestCompactAndMatchUIDSet(t *testing.T) {
	if got := compactUIDSet([]uint32{1, 2, 3, 7, 9, 10}); got != "1:3,7,9:10" {
		t.Fatalf("compact set=%q", got)
	}
	if !imapUIDSetContains("1:3,9,*", 10, 10) || imapUIDSetContains("1:3,9", 8, 10) {
		t.Fatal("UID set membership mismatch")
	}
}
