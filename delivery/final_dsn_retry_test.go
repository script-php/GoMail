package delivery

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gomail/config"
	"gomail/store"
)

func TestFinalDSNRetryAfterTransientMailboxFailure(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.com'); INSERT INTO accounts(id,domain_id,email,password_hash,is_active) VALUES(1,1,'sender@example.com','test',0)`); err != nil {
		t.Fatal(err)
	}
	if err := db.DefaultFolders(1); err != nil {
		t.Fatal(err)
	}
	queueID, err := db.EnqueueMessage(&store.QueueEntry{
		MailFrom: "sender@example.com", RcptTo: "recipient@example.net",
		RawMessage:  []byte("From: sender@example.com\r\nTo: recipient@example.net\r\nSubject: original\r\n\r\nbody"),
		MaxAttempts: 1, NextRetry: time.Now().UTC(), DSNNotify: "SUCCESS", DSNRet: "HDRS",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE outbound_queue SET status = 'sent' WHERE id = ?`, queueID); err != nil {
		t.Fatal(err)
	}
	w := &Worker{db: db, cfg: &config.Config{Server: config.ServerConfig{Hostname: "mail.example.com", Domain: "example.com"}}}
	w.processFinalDSNs()
	var attempts, sent int
	if err := db.QueryRow(`SELECT dsn_attempts, dsn_sent FROM outbound_queue WHERE id = ?`, queueID).Scan(&attempts, &sent); err != nil || attempts != 1 || sent != 0 {
		t.Fatalf("retry state attempts=%d sent=%d err=%v", attempts, sent, err)
	}
	if _, err := db.Exec(`UPDATE accounts SET is_active = 1 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	// A future retry is not attempted early, even after the mailbox recovers.
	w.processFinalDSNs()
	if err := db.QueryRow(`SELECT dsn_sent FROM outbound_queue WHERE id = ?`, queueID).Scan(&sent); err != nil || sent != 0 {
		t.Fatalf("early retry sent=%d err=%v", sent, err)
	}
	if _, err := db.Exec(`UPDATE outbound_queue SET dsn_retry_at = '1970-01-01 00:00:00' WHERE id = ?`, queueID); err != nil {
		t.Fatal(err)
	}
	w.processFinalDSNs()
	w.processFinalDSNs()
	var reports int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE account_id = 1 AND direction = 'inbound'`).Scan(&reports); err != nil || reports != 1 {
		t.Fatalf("mailbox reports=%d err=%v", reports, err)
	}
	if err := db.QueryRow(`SELECT dsn_sent FROM outbound_queue WHERE id = ?`, queueID).Scan(&sent); err != nil || sent != 1 {
		t.Fatalf("final DSN marker=%d err=%v", sent, err)
	}
	var raw []byte
	var headers string
	var size int64
	var mailFrom string
	if err := db.QueryRow(`SELECT raw_message, raw_headers, size, mail_from FROM messages WHERE account_id = 1 AND direction = 'inbound'`).Scan(&raw, &headers, &size, &mailFrom); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte("Return-Path: <>\r\n")) || !strings.HasPrefix(headers, "Return-Path: <>\r\n") || size != int64(len(raw)) || mailFrom != "" {
		t.Fatalf("invalid direct DSN delivery metadata: headers=%q size=%d rawSize=%d mailFrom=%q", headers, size, len(raw), mailFrom)
	}
}
