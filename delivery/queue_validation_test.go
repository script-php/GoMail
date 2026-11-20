package delivery

import (
	"errors"
	"strings"
	"testing"

	"gomail/smtp"
)

func TestQueueRejectsOverlongHeaderBeforeSaving(t *testing.T) {
	q := &Queue{}
	raw := []byte("From: sender@example.test\r\nSubject: " + strings.Repeat("a", 1000) + "\r\n\r\nbody\r\n")
	err := q.Enqueue("sender@example.test", []string{"recipient@example.test"}, raw, 1)
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("expected invalid message before database access, got %v", err)
	}
}

func TestQueueRejectsEmptyRecipientListBeforeSaving(t *testing.T) {
	q := &Queue{}
	raw := []byte("From: sender@example.test\r\n\r\nbody\r\n")
	if err := q.Enqueue("sender@example.test", nil, raw, 1); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("empty recipient list reached queue storage: %v", err)
	}
	if err := q.EnqueueTLSReport("sender@example.test", nil, raw); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("empty report recipient list reached queue storage: %v", err)
	}
	if err := q.EnqueueSubmission("sender@example.test", nil, SubmissionDSN{}, raw, 1); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("empty submission recipient list reached queue storage: %v", err)
	}
}

func TestQueueRejectsMalformedSubmittedDSNBeforeSaving(t *testing.T) {
	q := &Queue{}
	err := q.EnqueueSubmission("sender@example.test", []string{"recipient@example.test"}, SubmissionDSN{
		Notify: []string{"SUCCESS\r\nDATA"}, OriginalRecipient: []string{"recipient@example.test"}, Return: "FULL",
	}, []byte("From: sender@example.test\r\n\r\nbody\r\n"), 1)
	if err == nil || !strings.Contains(err.Error(), "invalid submitted DSN options") {
		t.Fatalf("malformed DSN metadata reached queue storage: %v", err)
	}
}

func TestDefaultDSNEnvelopeIDStaysWithinOutboundLimit(t *testing.T) {
	short := "<message@example.test>"
	if got := defaultDSNEnvelopeID(short); got != short {
		t.Fatalf("ordinary Message-ID changed: %q", got)
	}
	long := "<" + strings.Repeat("x", 200) + "@example.test>"
	got := defaultDSNEnvelopeID(long)
	if got == long || got != defaultDSNEnvelopeID(long) || len(got) > 100 {
		t.Fatalf("long Message-ID was not mapped to a stable bounded ENVID: %q", got)
	}
	if err := smtp.ValidateOutboundDSNEnvelopeID(got); err != nil {
		t.Fatalf("generated ENVID is invalid: %v", err)
	}
}
