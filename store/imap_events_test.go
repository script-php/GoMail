package store

import (
	"testing"
	"time"
)

func TestIMAPEventSubscriptionsAreAccountScopedAndCoalesced(t *testing.T) {
	db := openIMAPTestDB(t)
	accountOne, cancelOne := db.SubscribeIMAPChanges(1)
	defer cancelOne()
	accountTwo, cancelTwo := db.SubscribeIMAPChanges(2)
	defer cancelTwo()
	db.NotifyIMAPChanges(1)
	db.NotifyIMAPChanges(1)
	select {
	case <-accountOne:
	case <-time.After(time.Second):
		t.Fatal("account 1 subscriber was not notified")
	}
	select {
	case <-accountOne:
		t.Fatal("coalesced subscriber received duplicate pending event")
	default:
	}
	select {
	case <-accountTwo:
		t.Fatal("account 2 received account 1 event")
	default:
	}
	cancelOne()
	db.NotifyIMAPChanges(1)
	select {
	case <-accountOne:
		t.Fatal("cancelled subscriber received an event")
	default:
	}
}
