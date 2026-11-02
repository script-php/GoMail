package store

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"testing"

	"time"

	"gomail/config"
)

// Opt in with GOMAIL_TEST_MYSQL_ADDR=127.0.0.1:3307 and optional
// GOMAIL_TEST_MYSQL_USER / GOMAIL_TEST_MYSQL_PASSWORD. Set
// GOMAIL_TEST_MYSQL_DATABASE to use an existing empty test database. Without it,
// a generated disposable database is created and dropped.
func TestMySQLIntegration(t *testing.T) {
	addr := os.Getenv("GOMAIL_TEST_MYSQL_ADDR")
	if addr == "" {
		t.Skip("set GOMAIL_TEST_MYSQL_ADDR to run against a real MySQL server")
	}
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	user := os.Getenv("GOMAIL_TEST_MYSQL_USER")
	if user == "" {
		user = "root"
	}
	suppliedDatabase := os.Getenv("GOMAIL_TEST_MYSQL_DATABASE")
	databaseName := suppliedDatabase
	if databaseName == "" {
		databaseName = fmt.Sprintf("gomail_test_%d", time.Now().UnixNano())
	}
	testDomain := fmt.Sprintf("integration-%d.invalid", time.Now().UnixNano())
	cfg := config.StoreConfig{Database: "mysql", AttachmentsPath: t.TempDir(), MySQL: config.MySQLConfig{
		Host: host, Port: port, User: user, Password: os.Getenv("GOMAIL_TEST_MYSQL_PASSWORD"), Name: databaseName,
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if suppliedDatabase != "" {
		probe, err := mysqlConnection(mysqlDriverConfig(cfg.MySQL))
		if err != nil {
			t.Fatal(err)
		}
		defer probe.Close()
		rows, err := probe.Query(`SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE'`, databaseName)
		if err != nil {
			t.Fatal(err)
		}
		var tables []string
		for rows.Next() {
			var table string
			if err := rows.Scan(&table); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			tables = append(tables, table)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
		allowed := (&DB{}).parseSchemaDefinition(schemaSQL)
		for _, table := range tables {
			if table == "schema_migrations" {
				continue
			}
			if _, ok := allowed[table]; !ok {
				t.Fatalf("refusing to test database with unrelated table %s", table)
			}
			var count int
			if err := probe.QueryRow("SELECT COUNT(*) FROM " + quoteMySQL(table)).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("refusing to test non-empty table %s", table)
			}
		}
	}
	db, err := OpenConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if db != nil {
			defer db.Close()
		}
		cleanup, err := mysqlConnection(mysqlDriverConfig(cfg.MySQL))
		if err != nil {
			t.Error(err)
			return
		}
		defer cleanup.Close()
		if suppliedDatabase == "" {
			if _, err := cleanup.Exec("DROP DATABASE " + quoteMySQL(databaseName)); err != nil {
				t.Error(err)
			}
			return
		}
		// Remove only records created by this test, leaving the schema ready to use.
		for _, item := range []struct {
			query string
			args  []interface{}
		}{
			{`DELETE FROM outbound_queue WHERE rcpt_to = ?`, []interface{}{"queue@" + testDomain}},
			{`DELETE FROM sessions WHERE token IN (?, ?)`, []interface{}{testDomain, "expired-" + testDomain}},
			{`DELETE FROM greylisting WHERE recipient_domain = ?`, []interface{}{testDomain}},
			{`DELETE FROM tarpitting WHERE recipient_domain = ?`, []interface{}{testDomain}},
			{`DELETE FROM dmarc_feedback WHERE domain = ?`, []interface{}{testDomain}},
			{`DELETE FROM dmarc_report_log WHERE domain = ?`, []interface{}{testDomain}},
			{`DELETE FROM tls_failures WHERE recipient_domain = ?`, []interface{}{testDomain}},
			{`DELETE FROM domains WHERE domain = ?`, []interface{}{testDomain}},
		} {
			if _, err := cleanup.Exec(item.query, item.args...); err != nil {
				t.Error(err)
			}
		}
	})
	domain, err := db.CreateDomain(&Domain{Domain: testDomain, IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	account, err := db.CreateAccount(&Account{DomainID: domain, Email: "one@" + testDomain, IsActive: true, PasswordHash: "test"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := db.CreateAccount(&Account{DomainID: domain, Email: "two@" + testDomain, IsActive: true, PasswordHash: "test"})
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := db.GetFolderByType(account, "inbox")
	if err != nil || inbox == nil {
		t.Fatalf("folders: %v", err)
	}
	raw := bytes.Repeat([]byte("raw mail \x00"), 100000)
	message := &Message{AccountID: account, FolderID: &inbox.ID, MessageID: "mysql-test", Direction: "inbound", Subject: "Hello 🌍 10%_!", TextBody: "Unicode mail", RawMessage: raw, ReceivedAt: time.Now()}
	id, err := db.SaveMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.GetMessage(id, account)
	if err != nil || got == nil || !bytes.Equal(got.RawMessage, raw) || got.Subject != message.Subject {
		t.Fatalf("message round trip: %v", err)
	}
	if err = db.ApplyMessageAction(other, []int64{id}, "trash", 0); err == nil {
		t.Fatal("cross-account action accepted")
	}
	for _, action := range []string{"read", "unread", "trash", "restore"} {
		if err = db.ApplyMessageAction(account, []int64{id}, action, 0); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
	page, total, err := db.SearchMessagesPage(account, "%_!", 50, nil)
	if err != nil || total != 1 || len(page.Messages) != 1 {
		t.Fatalf("search: %d %v", total, err)
	}
	for _, value := range []string{"first", "second"} {
		if err = db.SaveSession(testDomain, value, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if value, err := db.GetSession(testDomain); err != nil || value != "second" {
		t.Fatalf("session upsert: %s %v", value, err)
	}
	if err = db.SaveSession("expired-"+testDomain, "expired", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = db.CleanExpiredSessions(); err != nil {
		t.Fatal(err)
	}
	if value, _ := db.GetSession("expired-" + testDomain); value != "" {
		t.Fatal("expired session retained")
	}
	for i := 0; i < 2; i++ {
		if err = db.DefaultFolders(account); err != nil {
			t.Fatal(err)
		}
		if err = db.IncrementTarpittingFailure(testDomain, "192.0.2.1", "RCPT"); err != nil {
			t.Fatal(err)
		}
		if err = db.UpdateLastDMARCReportTime(testDomain); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.CheckGreylist(testDomain, "192.0.2.1", "sender@remote.com", "one@"+testDomain, 0); err != nil {
		t.Fatal(err)
	}
	if status, err := db.CheckGreylist(testDomain, "192.0.2.1", "sender@remote.com", "one@"+testDomain, 0); err != nil || !status.DelayExpired {
		t.Fatalf("greylisting: %v", err)
	}
	if err = db.CleanupGreylisting(); err != nil {
		t.Fatal(err)
	}
	if err = db.CleanupTarpitting(); err != nil {
		t.Fatal(err)
	}
	if err = db.SaveDMARCFeedback(testDomain, "192.0.2.1", "remote.com", "pass", "pass", "none"); err != nil {
		t.Fatal(err)
	}
	if feedback, err := db.GetDMARCFeedbackForReport(testDomain, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)); err != nil || feedback["192.0.2.1"] != 1 {
		t.Fatalf("DMARC: %v", err)
	}
	if err = db.RecordTLSFailure(testDomain, "certificate-expired", "192.0.2.1", "mx."+testDomain, "192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	if failures, err := db.GetTLSFailuresForReport(testDomain, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)); err != nil || len(failures) != 1 || failures[0].AttemptedAt.IsZero() {
		t.Fatalf("TLS reports: %v", err)
	}
	var before int
	if err = db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	rollbackEntries := []*QueueEntry{
		{RcptTo: "queue@" + testDomain, RawMessage: raw, NextRetry: time.Now()},
		{RcptTo: "queue@" + testDomain, RawMessage: nil, NextRetry: time.Now()},
	}
	if _, err = db.SaveQueuedMessage(message, rollbackEntries); err == nil {
		t.Fatal("invalid queue batch succeeded")
	}
	var after, queuedCount int
	if err = db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM outbound_queue`).Scan(&queuedCount); err != nil {
		t.Fatal(err)
	}
	if after != before || queuedCount != 0 {
		t.Fatal("failed MySQL enqueue partially committed")
	}
	entries := []*QueueEntry{{RcptTo: "queue@" + testDomain, RawMessage: raw, NextRetry: time.Now().Add(-time.Minute), MaxAttempts: 6}}
	if _, err = db.SaveQueuedMessage(message, entries); err != nil {
		t.Fatal(err)
	}
	if _, err = db.SaveQueuedMessage(&Message{AccountID: 0}, entries); err != nil {
		t.Fatalf("system report: %v", err)
	}
	if queued, err := db.GetPendingQueue(10); err != nil || len(queued) != 2 {
		t.Fatalf("pending queue: %v %d", err, len(queued))
	}
	if _, err = db.Exec(`UPDATE outbound_queue SET status = 'sending', updated_at = ?`, databaseTime(time.Now().Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	if recovered, err := db.RecoverStaleQueueEntries(); err != nil || recovered != 2 {
		t.Fatalf("queue recovery: %d %v", recovered, err)
	}
	// Simulate an older schema: missing column and index, plus an extra custom column.
	for _, query := range []string{
		`ALTER TABLE domains DROP COLUMN greylisting_delay_minutes`,
		`ALTER TABLE domains ADD COLUMN gomail_integration_note VARCHAR(255) DEFAULT 'keep'`,
		`DROP INDEX idx_messages_received_at ON messages`,
	} {
		if _, err = db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	db, err = OpenConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var note string
	var delay, count int
	if err = db.QueryRow(`SELECT gomail_integration_note, greylisting_delay_minutes FROM domains WHERE id = ?`, domain).Scan(&note, &delay); err != nil || note != "keep" || delay != 15 {
		t.Fatalf("migration: %s %d %v", note, delay, err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = 'mailbox_folders_v1'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("migration repeated: %d %v", count, err)
	}
	if got, err := db.GetMessage(id, account); err != nil || got == nil || !bytes.Equal(got.RawMessage, raw) {
		t.Fatalf("restart lost message: %v", err)
	}
	if _, err = db.Exec(`ALTER TABLE domains DROP COLUMN gomail_integration_note`); err != nil {
		t.Fatal(err)
	}
	// FK behavior must match domain/account/message ownership.
	if err = db.DeleteAccount(account); err != nil {
		t.Fatal(err)
	}
	if got, err := db.GetMessage(id, account); err != nil || got != nil {
		t.Fatal("account deletion did not cascade")
	}
}
