package handlers

import (
	"testing"
	"time"

	"gomail/store"
)

func TestSignedMessageCursorScopeAndTampering(t *testing.T) {
	signer := newCursorSigner("secret")
	message := &store.Message{ID: 42, ReceivedAt: time.Unix(1234, 0)}
	encoded := signer.encode(7, "folder:9", "older", message)
	decoded, err := signer.decode(encoded, 7, "folder:9")
	if err != nil || decoded.ID != 42 || decoded.Direction != "older" || decoded.ReceivedAt.Unix() != 1234 {
		t.Fatalf("unexpected decode: %+v err=%v", decoded, err)
	}
	if _, err := signer.decode(encoded, 8, "folder:9"); err == nil {
		t.Fatal("cursor crossed account scope")
	}
	if _, err := signer.decode(encoded, 7, "folder:10"); err == nil {
		t.Fatal("cursor crossed folder scope")
	}
	if _, err := signer.decode(encoded+"x", 7, "folder:9"); err == nil {
		t.Fatal("tampered cursor was accepted")
	}
}
