package delivery

import (
	"errors"
	"strings"
	"testing"
)

func TestQueueRejectsOverlongHeaderBeforeSaving(t *testing.T) {
	q := &Queue{}
	raw := []byte("From: sender@example.test\r\nSubject: " + strings.Repeat("a", 1000) + "\r\n\r\nbody\r\n")
	err := q.Enqueue("sender@example.test", []string{"recipient@example.test"}, raw, 1)
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("expected invalid message before database access, got %v", err)
	}
}
