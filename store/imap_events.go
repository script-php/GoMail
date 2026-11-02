package store

type imapEventSubscription struct {
	accountID int64
	changes   chan struct{}
}

// SubscribeIMAPChanges registers a coalescing process-local mailbox change
// notification. The caller must invoke the returned cancel function.
func (db *DB) SubscribeIMAPChanges(accountID int64) (<-chan struct{}, func()) {
	db.imapEventsMu.Lock()
	defer db.imapEventsMu.Unlock()
	if db.imapEvents == nil {
		db.imapEvents = make(map[uint64]imapEventSubscription)
	}
	db.imapEventsNext++
	id := db.imapEventsNext
	changes := make(chan struct{}, 1)
	db.imapEvents[id] = imapEventSubscription{accountID: accountID, changes: changes}
	return changes, func() {
		db.imapEventsMu.Lock()
		delete(db.imapEvents, id)
		db.imapEventsMu.Unlock()
	}
}

// NotifyIMAPChanges wakes account sessions without blocking the committing
// mutation. A buffered signal coalesces bursts; IDLE always re-reads durable
// state before emitting protocol updates.
func (db *DB) NotifyIMAPChanges(accountIDs ...int64) {
	if len(accountIDs) == 0 {
		return
	}
	wanted := make(map[int64]bool, len(accountIDs))
	for _, accountID := range accountIDs {
		if accountID != 0 {
			wanted[accountID] = true
		}
	}
	db.imapEventsMu.Lock()
	defer db.imapEventsMu.Unlock()
	for _, subscription := range db.imapEvents {
		if !wanted[subscription.accountID] {
			continue
		}
		select {
		case subscription.changes <- struct{}{}:
		default:
		}
	}
}
