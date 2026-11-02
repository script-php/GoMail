package backup

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"gomail/config"
	"gomail/store"
)

// Opt in with GOMAIL_TEST_MYSQL_CONFIG pointing at an existing GoMail config.
// The test creates two uniquely named disposable databases and never targets
// the configured production database.
func TestMySQLBackupRestoreIsolatedRoundTrip(t *testing.T) {
	path := os.Getenv("GOMAIL_TEST_MYSQL_CONFIG")
	if path == "" {
		t.Skip("set GOMAIL_TEST_MYSQL_CONFIG for an isolated MySQL restore drill")
	}
	base, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if base.Store.Database != "mysql" {
		t.Fatal("test config must use MySQL")
	}
	root := t.TempDir()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	sourceName := "gomail_backup_src_" + suffix
	targetName := "gomail_backup_dst_" + suffix
	created := make(map[string]bool)
	source := *base
	source.Store = base.Store
	source.Store.MySQL = base.Store.MySQL
	source.Store.MySQL.Name = sourceName
	source.Store.AttachmentsPath = filepath.Join(root, "source-attachments")
	target := source
	target.Store = source.Store
	target.Store.MySQL = source.Store.MySQL
	target.Store.MySQL.Name = targetName
	target.Store.AttachmentsPath = filepath.Join(root, "target-attachments")
	// DROP is restricted to exact generated names, never a configured database.
	t.Cleanup(func() {
		for _, name := range []string{sourceName, targetName} {
			if !created[name] {
				continue
			}
			driverCfg := mysql.NewConfig()
			driverCfg.User = base.Store.MySQL.User
			driverCfg.Passwd = base.Store.MySQL.Password
			driverCfg.Net = "tcp"
			driverCfg.Addr = net.JoinHostPort(base.Store.MySQL.Host, fmt.Sprint(base.Store.MySQL.Port))
			conn, err := sql.Open("mysql", driverCfg.FormatDSN())
			if err != nil {
				t.Error(err)
				continue
			}
			_, err = conn.Exec("DROP DATABASE `" + name + "`")
			conn.Close()
			if err != nil {
				t.Errorf("cleaning disposable database %s: %v", name, err)
			}
		}
	})
	configPath := filepath.Join(root, "source.json")
	configBytes, err := json.Marshal(&source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenConfig(source.Store)
	if err != nil {
		t.Fatalf("creating disposable source database: %v", err)
	}
	created[sourceName] = true
	domainID, err := db.CreateDomain(&store.Domain{Domain: "backup.invalid", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "user@backup.invalid", PasswordHash: "hash", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := db.GetFolderByType(accountID, "inbox")
	if err != nil {
		t.Fatal(err)
	}
	messageID, err := db.SaveMessage(&store.Message{AccountID: accountID, FolderID: &inbox.ID, MessageID: "backup-fixture", Direction: "inbound", Subject: "Restore fixture", TextBody: "safe body", ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source.Store.AttachmentsPath, "fixture.bin"), []byte("attachment fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveAttachment(&store.Attachment{MessageID: messageID, Filename: "fixture.bin", ContentType: "application/octet-stream", Size: 18, StoragePath: "fixture.bin"}); err != nil {
		t.Fatal(err)
	}
	queueID, err := db.EnqueueMessage(&store.QueueEntry{MailFrom: "user@backup.invalid", RcptTo: "remote@example.net", RawMessage: []byte("From: user@backup.invalid\r\n\r\nfixture"), MaxAttempts: 6, NextRetry: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	token, claimed, err := db.ClaimQueueEntry(queueID)
	if err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	if err := db.TransitionOwnedQueueEntryWithCode(queueID, token, "failed", 1, time.Now(), "remote 550 rejected", 550, ""); err != nil {
		t.Fatal(err)
	}
	db.Close()
	archivePath := filepath.Join(root, "archive.tar.gz")
	manifest, err := Create(&source, configPath, archivePath, "mysql-test")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Counts["outbound_queue_events"] != 2 {
		t.Fatalf("history manifest count=%d", manifest.Counts["outbound_queue_events"])
	}
	if _, err := Verify(archivePath); err != nil {
		t.Fatal(err)
	}
	targetDB, err := store.OpenConfig(target.Store)
	if err != nil {
		t.Fatalf("creating disposable target database: %v", err)
	}
	created[targetName] = true
	targetDB.Close()
	targetConfigPath := filepath.Join(root, "target.json")
	if err := os.WriteFile(targetConfigPath, []byte("before restore"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(&target, targetConfigPath, archivePath, true); err != nil {
		t.Fatal(err)
	}
	restoredConfig, err := os.ReadFile(targetConfigPath)
	if err != nil || string(restoredConfig) != string(configBytes) {
		t.Fatalf("config restore mismatch: %v", err)
	}
	attachment, err := os.ReadFile(filepath.Join(target.Store.AttachmentsPath, "fixture.bin"))
	if err != nil || string(attachment) != "attachment fixture" {
		t.Fatalf("attachment restore mismatch: %v", err)
	}
	restored, err := store.OpenConfig(target.Store)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	counts, err := restored.BackupCounts()
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"domains", "accounts", "messages", "attachments", "outbound_queue", "outbound_queue_events"} {
		if counts[table] != manifest.Counts[table] {
			t.Fatalf("%s count: %d want %d", table, counts[table], manifest.Counts[table])
		}
	}
	events, err := restored.ListQueueEvents(queueID, 10)
	if err != nil || len(events) != 2 || events[0].SMTPCode != 550 {
		t.Fatalf("history restore mismatch: %+v %v", events, err)
	}
}
