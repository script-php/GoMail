package handlers

import (
	"io"
	"mime/quotedprintable"
	"strings"
	"testing"
	"time"

	"gomail/store"
)

func TestForwardSubjectDoesNotDuplicatePrefix(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"Hello", "Fwd: Hello"},
		{"Fwd: Hello", "Fwd: Hello"},
		{"fWD: Hello", "fWD: Hello"},
	} {
		if got := forwardSubject(tc.input); got != tc.want {
			t.Errorf("forwardSubject(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestForwardInlineTextLongLinesAreEncodedWithoutChangingOriginal(t *testing.T) {
	original := &store.Message{
		FromAddr:   "sender@example.net",
		ToAddr:     "recipient@example.test",
		Subject:    "Subject",
		TextBody:   strings.Repeat("x", 1500) + "\nsecond line café",
		ReceivedAt: time.Date(2026, 9, 23, 10, 30, 0, 0, time.UTC),
	}
	text := forwardInlineText(strings.Repeat("n", 1500), original)
	encoded := encodeComposeTextBody(text)
	for _, line := range strings.Split(encoded, "\r\n") {
		if len(line)+2 > 1000 {
			t.Fatalf("forward text has an overlong SMTP line: %d", len(line)+2)
		}
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(encoded)))
	if err != nil || string(decoded) != text {
		t.Fatalf("forward text did not round trip: err=%v", err)
	}
	if !strings.Contains(text, original.TextBody[:1500]) || !strings.Contains(text, "second line café") {
		t.Fatal("forwarded text omits original content")
	}
}

func TestBuildForwardedRFC822FallbackContainsOriginal(t *testing.T) {
	original := &store.Message{
		FromAddr:   "sender@example.net",
		ToAddr:     "recipient@example.com",
		Subject:    "Original subject",
		MessageID:  "original@example.net",
		TextBody:   "first line\nsecond line",
		ReceivedAt: time.Date(2026, 9, 23, 10, 30, 0, 0, time.UTC),
	}

	got := buildForwardedRFC822(original)
	for _, want := range []string{
		"From: sender@example.net\r\n",
		"Subject: Original subject\r\n",
		"Message-ID: <original@example.net>\r\n",
		"first line\r\nsecond line",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("fallback message does not contain %q:\n%s", want, got)
		}
	}
}

func TestBuildForwardedRFC822FallbackPreservesInternationalAddress(t *testing.T) {
	got := buildForwardedRFC822(&store.Message{FromAddr: "zoë@example.net", ToAddr: "recipient@example.com", Subject: "café"})
	if !strings.Contains(got, "From: zoë@example.net\r\n") || strings.Contains(got, "From: =?") {
		t.Fatalf("fallback encoded the addr-spec: %q", got)
	}
}

func TestForwardBodyHelpersPreventInjectedMetadataLines(t *testing.T) {
	if got := singleLineBodyValue("subject\r\nBcc: victim@example.net"); strings.Contains(got, "\r") || strings.Contains(got, "\n") {
		t.Fatalf("single-line value retained a newline: %q", got)
	}
	if got := normalizeBodyLineEndings("one\ntwo\rthree\r\nfour"); got != "one\r\ntwo\r\nthree\r\nfour" {
		t.Fatalf("unexpected normalized body: %q", got)
	}
}

func TestReplyContentAndSubject(t *testing.T) {
	original := &store.Message{
		FromAddr:   "sender@example.net",
		Subject:    "Question",
		TextBody:   "first line\r\nsecond line",
		ReceivedAt: time.Date(2026, 9, 23, 10, 30, 0, 0, time.UTC),
	}

	if got := replySubject(original.Subject); got != "Re: Question" {
		t.Fatalf("reply subject = %q", got)
	}
	if got := replySubject("RE: Question"); got != "RE: Question" {
		t.Fatalf("reply subject duplicated prefix: %q", got)
	}

	body := quotedReplyBody(original)
	for _, want := range []string{
		"On Wed, 23 Sep 2026 at 10:30, sender@example.net wrote:",
		"> first line\n> second line",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("quoted reply does not contain %q: %q", want, body)
		}
	}
}
