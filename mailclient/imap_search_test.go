package mailclient

import (
	"testing"
	"time"

	"gomail/store"
)

func TestIMAPSearchGrammar(t *testing.T) {
	refs := []store.IMAPMessageRef{
		{MessageID: 10, Sequence: 1, UID: 7, Recent: true, Keywords: []string{"project"}},
		{MessageID: 20, Sequence: 2, UID: 11, Seen: true, Flagged: true},
	}
	messages := map[int64]*store.Message{
		10: {ID: 10, Subject: "Alpha release", Size: 120, ReceivedAt: time.Date(2026, 10, 10, 18, 0, 0, 0, time.UTC), RawMessage: []byte("Date: Fri, 9 Oct 2026 12:00:00 +0000\r\nFrom: Alice <alice@example.net>\r\nTo: team@example.com\r\nX-Project: GoMail\r\nSubject: Alpha release\r\n\r\nfirst body")},
		20: {ID: 20, Subject: "Beta report", Size: 500, ReceivedAt: time.Date(2026, 10, 15, 18, 0, 0, 0, time.UTC), RawMessage: []byte("Date: Thu, 15 Oct 2026 12:00:00 +0000\r\nFrom: Bob <bob@example.net>\r\nTo: team@example.com\r\nSubject: Beta report\r\n\r\nsecond body")},
	}
	tests := []struct {
		name   string
		tokens []string
		want   []int64
	}{
		{"group-and-not", []string{"(", "SUBJECT", "Alpha", "NOT", "SEEN", ")"}, []int64{10}},
		{"or", []string{"OR", "FROM", "alice", "FLAGGED"}, []int64{10, 20}},
		{"header-date", []string{"HEADER", "X-Project", "gomail", "SENTBEFORE", "10-Oct-2026"}, []int64{10}},
		{"missing-empty-header", []string{"HEADER", "X-Missing", ""}, nil},
		{"internal-date-size", []string{"SINCE", "15-Oct-2026", "LARGER", "200"}, []int64{20}},
		{"keyword", []string{"KEYWORD", "PROJECT"}, []int64{10}},
		{"sequence", []string{"2"}, []int64{20}},
		{"uid", []string{"UID", "7"}, []int64{10}},
		{"new", []string{"NEW"}, []int64{10}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			predicate, err := parseIMAPSearch(test.tokens, refs)
			if err != nil {
				t.Fatal(err)
			}
			var got []int64
			for _, ref := range refs {
				if predicate(ref, messages[ref.MessageID]) {
					got = append(got, ref.MessageID)
				}
			}
			if len(got) != len(test.want) {
				t.Fatalf("matches=%v want=%v", got, test.want)
			}
			for index := range got {
				if got[index] != test.want[index] {
					t.Fatalf("matches=%v want=%v", got, test.want)
				}
			}
		})
	}
}

func TestIMAPSearchRejectsMalformedExpressions(t *testing.T) {
	refs := []store.IMAPMessageRef{{MessageID: 1, Sequence: 1, UID: 1}}
	for _, tokens := range [][]string{
		{"("}, {"NOT"}, {"OR", "ALL"}, {"HEADER", "Bad:Field", "x"},
		{"KEYWORD", "bad\\flag"}, {"SINCE", "not-a-date"}, {"UID", "0"}, {"BOGUS"},
	} {
		if _, err := parseIMAPSearch(tokens, refs); err == nil {
			t.Fatalf("accepted malformed SEARCH: %q", tokens)
		}
	}
}

func TestLexIMAPSearchGroupsButPreservesQuotedParentheses(t *testing.T) {
	tokens, err := lexIMAP(`a1 SEARCH (OR SUBJECT "(alpha)" SUBJECT beta) NOT SEEN`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a1", "SEARCH", "(", "OR", "SUBJECT", "(alpha)", "SUBJECT", "beta", ")", "NOT", "SEEN"}
	if len(tokens) != len(want) {
		t.Fatalf("tokens=%q want=%q", tokens, want)
	}
	for index := range tokens {
		if tokens[index] != want[index] {
			t.Fatalf("tokens=%q want=%q", tokens, want)
		}
	}
}
