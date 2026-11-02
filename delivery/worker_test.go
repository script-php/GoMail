package delivery

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gomail/config"
	"gomail/store"
)

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
	if err := w.deliverDSN("sender@example.test", report, 0); err == nil {
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

func TestLocalRecipientRejectsMalformedAddress(t *testing.T) {
	w := &Worker{}
	local, err := w.isLocalRecipient("missing-at-sign")
	if err == nil || local {
		t.Fatalf("malformed route = %v, %v; want false and an error", local, err)
	}
}
