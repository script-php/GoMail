package mailclient

import (
	"testing"

	"gomail/store"
)

func TestResolveIMAPSequenceSet(t *testing.T) {
	refs := []store.IMAPMessageRef{{Sequence: 1, UID: 4}, {Sequence: 2, UID: 9}, {Sequence: 3, UID: 12}}
	for _, tc := range []struct {
		value string
		uid   bool
		want  []uint32
	}{
		{value: "1:*", want: []uint32{4, 9, 12}},
		{value: "3:2", want: []uint32{9, 12}},
		{value: "1,3", want: []uint32{4, 12}},
		{value: "4:9", uid: true, want: []uint32{4, 9}},
		{value: "9:*", uid: true, want: []uint32{9, 12}},
	} {
		got, err := resolveIMAPSequenceSet(tc.value, refs, tc.uid)
		if err != nil {
			t.Fatalf("%s: %v", tc.value, err)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("%s: got %#v want %v", tc.value, got, tc.want)
		}
		for index := range got {
			if got[index].UID != tc.want[index] {
				t.Fatalf("%s: UID[%d]=%d want %d", tc.value, index, got[index].UID, tc.want[index])
			}
		}
	}
	for _, invalid := range []string{"", "0", "a", "1:2:3"} {
		if _, err := resolveIMAPSequenceSet(invalid, refs, false); err == nil {
			t.Fatalf("accepted invalid set %q", invalid)
		}
	}
}

func TestIMAPListPatterns(t *testing.T) {
	tests := []struct {
		pattern, name string
		want          bool
	}{
		{"*", "Projects/GoMail/Archive", true},
		{"%", "Projects", true},
		{"%", "Projects/GoMail", false},
		{"Projects/%", "Projects/GoMail", true},
		{"Projects/%", "Projects/GoMail/Archive", false},
		{"Projects/*/Archive", "Projects/GoMail/Archive", true},
		{"projects/%", "Projects/GoMail", true},
	}
	for _, test := range tests {
		if got := imapPatternMatches(test.pattern, test.name); got != test.want {
			t.Errorf("pattern %q name %q = %v, want %v", test.pattern, test.name, got, test.want)
		}
	}
}
