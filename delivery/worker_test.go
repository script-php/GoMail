package delivery

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gomail/config"
	"gomail/smtp"
	"gomail/store"
)

func TestLocalDeliveryAcceptsHeaderOnlyMessage(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "bob@example.test", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: alice@example.test\r\nTo: bob@example.test\r\nSubject: header only\r\n")
	w := &Worker{db: db, cfg: &config.Config{Server: config.ServerConfig{Hostname: "mx.example.test"}}}
	verp := "alice+v1-bob=example-test@example.test"
	if err := w.deliverLocal(&store.QueueEntry{MailFrom: "alice@example.test", VERPBounceAddress: verp, RcptTo: "bob@example.test"}, raw); err != nil {
		t.Fatalf("local delivery rejected header-only message: %v", err)
	}
	var stored []byte
	var envelopeFrom string
	if err := db.QueryRow(`SELECT raw_message, mail_from FROM messages WHERE account_id = ?`, accountID).Scan(&stored, &envelopeFrom); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(stored, []byte("Subject: header only\r\n\r\n")) || !bytes.HasPrefix(stored, []byte("Return-Path: <"+verp+">\r\n")) || envelopeFrom != verp {
		t.Fatalf("header-only local copy was not finalized: %q", stored)
	}
}

func TestUnicodeRecipientDomainStaysLocal(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&store.Domain{Domain: "xn--bcher-kva.example", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "bob@xn--bcher-kva.example", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	w := &Worker{db: db, cfg: &config.Config{Server: config.ServerConfig{Hostname: "mx.example.test"}}}
	local, err := w.isLocalRecipient("bob@bücher.example")
	if err != nil || !local {
		t.Fatalf("Unicode domain local=%v err=%v", local, err)
	}
	raw := []byte("From: alice@example.test\r\nTo: bob@xn--bcher-kva.example\r\nSubject: test\r\n\r\nhello\r\n")
	if err := w.deliverLocal(&store.QueueEntry{MailFrom: "alice@example.test", RcptTo: "bob@bücher.example"}, raw); err != nil {
		t.Fatalf("local delivery via Unicode domain: %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE account_id=?`, accountID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("inbox copies=%d err=%v", count, err)
	}
}

func TestQueuedLocalDeliveryRejectsDisabledDomain(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "bob@example.test", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE domains SET is_active=0 WHERE id=?`, domainID); err != nil {
		t.Fatal(err)
	}
	w := &Worker{db: db, cfg: &config.Config{Server: config.ServerConfig{Hostname: "mx.example.test"}}}
	local, err := w.isLocalRecipient("bob@example.test")
	if err != nil || !local {
		t.Fatalf("disabled hosted domain must retain local routing: local=%v err=%v", local, err)
	}
	raw := []byte("From: alice@example.test\r\nTo: bob@example.test\r\n\r\nhello\r\n")
	err = w.deliverLocal(&store.QueueEntry{MailFrom: "alice@example.test", RcptTo: "bob@example.test", LocalRecipient: true}, raw)
	if !errors.Is(err, errLocalDomainInactive) {
		t.Fatalf("disabled domain delivery error=%v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE account_id=?`, accountID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("disabled domain mailbox copies=%d err=%v", count, err)
	}
}

func TestClaimedLocalDeliveryCommitsMailboxAndQueueTogether(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "bob@example.test", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: alice@example.test\r\nTo: bob@example.test\r\nSubject: once\r\n\r\nhello\r\n")
	entry := &store.QueueEntry{MailFrom: "alice@example.test", RcptTo: "bob@example.test", RawMessage: raw, MaxAttempts: 3, NextRetry: time.Now().Add(-time.Minute)}
	entry.ID, err = db.EnqueueMessage(entry)
	if err != nil {
		t.Fatal(err)
	}
	token, claimed, err := db.ClaimQueueEntry(entry.ID)
	if err != nil || !claimed {
		t.Fatalf("queue claim=%v err=%v", claimed, err)
	}
	w := &Worker{db: db, cfg: &config.Config{Server: config.ServerConfig{Hostname: "mx.example.test"}}}
	if err := w.deliverLocalClaimed(entry, token, raw); err != nil {
		t.Fatal(err)
	}
	status, err := db.QueueEntryStatus(entry.ID)
	if err != nil || status != "sent" {
		t.Fatalf("queue status=%q err=%v", status, err)
	}
	if err := w.deliverLocalClaimed(entry, token, raw); !errors.Is(err, store.ErrQueueClaimLost) {
		t.Fatalf("reused claim error=%v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE account_id=?`, accountID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("mailbox copies=%d err=%v", count, err)
	}
}

func TestNullEnvelopeDSNDeliversLocally(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "sender@example.test", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	queueID, err := db.EnqueueMessage(&store.QueueEntry{MailFrom: "", RcptTo: "sender@example.test", RawMessage: []byte("From: Mailer-Daemon@example.test\r\nTo: sender@example.test\r\nSubject: Delivery report\r\n\r\nDelivered.\r\n"), MaxAttempts: 3, NextRetry: time.Now().Add(-time.Minute), DSNNotify: "NEVER"})
	if err != nil {
		t.Fatal(err)
	}
	w := &Worker{db: db, cfg: &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test", Domain: "example.test"}}, claimMu: &sync.Mutex{}}
	w.processQueue()
	status, err := db.QueueEntryStatus(queueID)
	if err != nil || status != "sent" {
		t.Fatalf("null-envelope DSN status=%q err=%v", status, err)
	}
	inbox, err := db.GetFolderByType(accountID, "inbox")
	if err != nil || inbox == nil {
		t.Fatalf("inbox=%v err=%v", inbox, err)
	}
}

func TestMissingLocalMailboxFailsWithoutRetry(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	senderID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "alice@example.test", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.EnqueueMessage(&store.QueueEntry{OriginAccountID: senderID, MailFrom: "alice@example.test", RcptTo: "deleted@example.test", RawMessage: []byte("From: alice@example.test\r\nTo: deleted@example.test\r\n\r\nhello\r\n"), MaxAttempts: 6, NextRetry: time.Now().Add(-time.Minute), DSNNotify: "NEVER"})
	if err != nil {
		t.Fatal(err)
	}
	w := &Worker{db: db, cfg: &config.Config{Server: config.ServerConfig{Hostname: "mx.example.test", Domain: "example.test"}}, claimMu: &sync.Mutex{}}
	w.processQueue()
	var status string
	var attempts, code int
	if err := db.QueryRow(`SELECT status, attempts FROM outbound_queue WHERE id = ?`, id).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT smtp_code FROM outbound_queue_events WHERE queue_id = ? AND event_type = 'final_failure' ORDER BY id DESC LIMIT 1`, id).Scan(&code); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || attempts != 1 || code != 550 {
		t.Fatalf("missing mailbox status=%q attempts=%d code=%d", status, attempts, code)
	}
}

func TestInactiveLocalMailboxFailsWithoutRetry(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	senderID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "alice@example.test", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "bob@example.test", PasswordHash: "unused", IsActive: false}); err != nil {
		t.Fatal(err)
	}
	id, err := db.EnqueueMessage(&store.QueueEntry{OriginAccountID: senderID, MailFrom: "alice@example.test", RcptTo: "bob@example.test", RawMessage: []byte("From: alice@example.test\r\nTo: bob@example.test\r\n\r\nhello\r\n"), MaxAttempts: 6, NextRetry: time.Now().Add(-time.Minute), DSNNotify: "NEVER"})
	if err != nil {
		t.Fatal(err)
	}
	w := &Worker{db: db, cfg: &config.Config{Server: config.ServerConfig{Hostname: "mx.example.test", Domain: "example.test"}}, claimMu: &sync.Mutex{}}
	w.processQueue()
	var status string
	var attempts, code int
	if err := db.QueryRow(`SELECT status, attempts FROM outbound_queue WHERE id = ?`, id).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT smtp_code FROM outbound_queue_events WHERE queue_id = ? AND event_type = 'final_failure' ORDER BY id DESC LIMIT 1`, id).Scan(&code); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || attempts != 1 || code != 550 {
		t.Fatalf("inactive mailbox status=%q attempts=%d code=%d", status, attempts, code)
	}
}

func TestPeriodicRecoveryQuarantinesStaleClaim(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id, err := db.EnqueueMessage(&store.QueueEntry{MailFrom: "a@example.test", RcptTo: "b@remote.test", RawMessage: []byte("From: a@example.test\r\n\r\nbody\r\n"), MaxAttempts: 3, NextRetry: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.ClaimQueueEntry(id); err != nil || !claimed {
		t.Fatalf("claim: %v, %v", claimed, err)
	}
	if _, err := db.Exec(`UPDATE outbound_queue SET updated_at = ? WHERE id = ?`, time.Now().Add(-time.Hour).UTC().Format("2006-01-02 15:04:05"), id); err != nil {
		t.Fatal(err)
	}
	p := &Pool{db: db, quit: make(chan struct{})}
	done := make(chan struct{})
	go func() { p.runQueueRecovery(10 * time.Millisecond); close(done) }()
	defer func() { close(p.quit); <-done }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status, err := db.QueueEntryStatus(id)
		if err != nil {
			t.Fatal(err)
		}
		if status == "uncertain" {
			if pending, err := db.GetPendingQueue(10); err != nil || len(pending) != 0 {
				t.Fatalf("uncertain delivery automatically requeued: %d, %v", len(pending), err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("periodic recovery did not quarantine the stale claim")
}

func TestQuotedLocalPartAtUsesFinalDomain(t *testing.T) {
	if got := parseRecipientDomain(`"sales@east"@example.net`); got != "example.net" {
		t.Fatalf("recipient domain=%q", got)
	}
	if got := extractDomain(`"sender@desk"@example.test`); got != "example.test" {
		t.Fatalf("sender domain=%q", got)
	}
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	w := &Worker{db: db}
	local, err := w.isLocalRecipient(`"sales@east"@example.test`)
	if err != nil || !local {
		t.Fatalf("quoted local recipient routed local=%v err=%v", local, err)
	}
	local, err = w.isLocalRecipient(`"sales@east"@remote.test`)
	if err != nil || local {
		t.Fatalf("remote quoted local recipient routed local=%v err=%v", local, err)
	}
}

func TestOutboundDSNRequiresInbox(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "sender@example.test", PasswordHash: "unused", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM folders WHERE account_id = ? AND folder_type = 'inbox'`, accountID); err != nil {
		t.Fatal(err)
	}
	w := &Worker{db: db, cfg: &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test", Domain: "example.test"}}}
	report := "From: mailer-daemon@example.test\r\nTo: sender@example.test\r\nSubject: Delivery failed\r\n\r\nFailure.\r\n"
	if err := w.deliverDSN("sender@example.test", report, 0, 0, "failed"); err == nil {
		t.Fatal("DSN saved without an inbox")
	}
}

func TestDeliveryFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		message   string
		permanent bool
	}{
		{"MX lookup: temporary DNS failure", false},
		{"dial tcp: connection refused", false},
		{"RCPT TO rejected by mx.example: 450 mailbox busy", false},
		{"RCPT TO rejected by mx.example: 499 temporary error", false},
		{"RCPT TO rejected by mx.example: 550 user unknown", true},
		{"RCPT TO rejected by mx.example: 503 bad command sequence", true},
		{"RCPT TO rejected by mx.example: 599 permanent error", true},
		{"MTA-STS policy for example.test: policy endpoint returned HTTP 503", false},
		{"all MX hosts failed: 554 5.6.3 8BITMIME required", true},
		{"all MX hosts failed: 554 5.6.0 SMTPUTF8 required", true},
		{"MX lookup: no-route.example: 550 5.1.2 recipient domain has no MX or address records", true},
	} {
		if got := isPermanentFailure(extractSMTPCode(tc.message)); got != tc.permanent {
			t.Errorf("%q: permanent=%v", tc.message, got)
		}
	}
}

func TestWorkerCancelsQueuedMailAfterSenderDisabled(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO accounts(id,domain_id,email,password_hash,is_active) VALUES(1,1,'alice@example.test','unused',0)`); err != nil {
		t.Fatal(err)
	}
	id, err := db.EnqueueMessage(&store.QueueEntry{OriginAccountID: 1, MailFrom: "alice@example.test", RcptTo: "bob@remote.test", RawMessage: []byte("From: alice@example.test\r\n\r\nhello"), MaxAttempts: 3, NextRetry: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	w := &Worker{db: db, claimMu: &sync.Mutex{}}
	w.processQueue()
	status, err := db.QueueEntryStatus(id)
	if err != nil || status != "cancelled" {
		t.Fatalf("queued sender was delivered or retried: status=%q err=%v", status, err)
	}
}

func TestLocalRecipientRoutingFailsClosedOnDatabaseError(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "mail.db"), filepath.Join(t.TempDir(), "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	w := &Worker{db: db}
	if _, err := db.Exec(`INSERT INTO domains(domain) VALUES(?)`, "local.example"); err != nil {
		t.Fatal(err)
	}
	local, err := w.isLocalRecipient("user@local.example")
	if err != nil || !local {
		t.Fatalf("local route = %v, %v; want true, nil", local, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	local, err = w.isLocalRecipient("user@local.example")
	if err == nil || local {
		t.Fatalf("closed database route = %v, %v; want false and an error", local, err)
	}
}

func TestDisabledHostedDomainNeverBecomesExternalRoute(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "mail.db"), filepath.Join(t.TempDir(), "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&store.Domain{Domain: "hosted.example", IsActive: false})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "bob@hosted.example", PasswordHash: "unused", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	w := &Worker{db: db}
	local, err := w.isLocalRecipient("bob@hosted.example")
	if err != nil || !local {
		t.Fatalf("disabled hosted domain route = local %v, err %v; want local", local, err)
	}
	if err := w.deliverLocal(&store.QueueEntry{RcptTo: "bob@hosted.example", MailFrom: "alice@other.example"}, []byte("From: alice@other.example\r\n\r\nhello\r\n")); !errors.Is(err, errLocalDomainInactive) {
		t.Fatalf("disabled hosted mailbox must fail locally: %v", err)
	}
	local, err = w.isLocalRecipient("bob@remote.example")
	if err != nil || local {
		t.Fatalf("unhosted domain route = local %v, err %v; want remote", local, err)
	}
}

func TestQueuedLocalRouteSurvivesDomainDeletion(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "mail.db"), filepath.Join(t.TempDir(), "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&store.Domain{Domain: "hosted.example", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	queueID, err := db.EnqueueMessage(&store.QueueEntry{MailFrom: "", RcptTo: "bob@hosted.example", RawMessage: []byte("From: service@hosted.example\r\n\r\nbody\r\n"), MaxAttempts: 3, NextRetry: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate deletion by another database administrator, bypassing GoMail's
	// normal guard. The persisted routing decision must still be fail-closed.
	if _, err := db.Exec(`DELETE FROM domains WHERE id=?`, domainID); err != nil {
		t.Fatal(err)
	}
	w := &Worker{db: db, claimMu: &sync.Mutex{}}
	w.processQueue()
	status, err := db.QueueEntryStatus(queueID)
	if err != nil || status != "failed" {
		t.Fatalf("deleted local domain was routed externally or retried: status=%q err=%v", status, err)
	}
}

func TestLocalRecipientRejectsMalformedAddress(t *testing.T) {
	w := &Worker{}
	local, err := w.isLocalRecipient("missing-at-sign")
	if err == nil || local {
		t.Fatalf("malformed route = %v, %v; want false and an error", local, err)
	}
	if code := smtp.SMTPFailureCode(fmt.Errorf("checking recipient route: %w", err)); code != 553 {
		t.Fatalf("malformed route code = %d; want permanent 553", code)
	}
	if code := extractSMTPCode(fmt.Errorf("checking recipient route: %w", err).Error()); code != 553 {
		t.Fatalf("persisted malformed route code = %d; want 553", code)
	}
}
