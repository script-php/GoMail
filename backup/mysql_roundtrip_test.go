package backup

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	fixedDB := os.Getenv("GOMAIL_TEST_MYSQL_FIXED_DB")
	if fixedDB != "" {
		if fixedDB != "gomailtest" || fixedDB == base.Store.MySQL.Name {
			t.Fatal("fixed test database must be gomailtest and differ from the configured database")
		}
		base.Store.MySQL.Name = fixedDB
		base.Store.MySQL.User = os.Getenv("GOMAIL_TEST_MYSQL_USER")
		base.Store.MySQL.Password = os.Getenv("GOMAIL_TEST_MYSQL_PASSWORD")
		if base.Store.MySQL.User == "" || base.Store.MySQL.Password == "" {
			t.Fatal("fixed test database credentials are required")
		}
		probe, err := sql.Open("mysql", mysqlDSN(base.Store.MySQL))
		if err != nil {
			t.Fatal(err)
		}
		var tables int
		err = probe.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = ?", fixedDB).Scan(&tables)
		probe.Close()
		if err != nil || tables != 0 {
			t.Fatalf("fixed test database must be empty before the drill (tables=%d): %v", tables, err)
		}
		t.Cleanup(func() {
			conn, err := sql.Open("mysql", mysqlDBDSN(base.Store.MySQL))
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			rows, err := conn.Query("SELECT table_name FROM information_schema.tables WHERE table_schema = ?", fixedDB)
			if err != nil {
				t.Error(err)
				return
			}
			var names []string
			for rows.Next() {
				var name string
				if err := rows.Scan(&name); err != nil {
					t.Error(err)
					break
				}
				names = append(names, "`"+name+"`")
			}
			rows.Close()
			if len(names) > 0 {
				if _, err := conn.Exec("SET FOREIGN_KEY_CHECKS=0"); err != nil {
					t.Error(err)
				} else if _, err := conn.Exec("DROP TABLE IF EXISTS " + strings.Join(names, ",")); err != nil {
					t.Error(err)
				}
			}
		})
	}
	root := t.TempDir()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	sourceName := "gomail_backup_src_" + suffix
	targetName := "gomail_backup_dst_" + suffix
	if fixedDB != "" {
		sourceName, targetName = fixedDB, fixedDB
	}
	created := make(map[string]bool)
	source := *base
	source.Store = base.Store
	source.Store.MySQL = base.Store.MySQL
	source.Store.MySQL.Name = sourceName
	source.Store.AttachmentsPath = filepath.Join(root, "source-attachments")
	source.TLS = base.TLS
	source.TLS.ACMEDir = filepath.Join(root, "source-acme")
	if err := os.MkdirAll(source.TLS.ACMEDir, 0700); err != nil {
		t.Fatal(err)
	}
	target := source
	target.Store = source.Store
	target.Store.MySQL = source.Store.MySQL
	target.Store.MySQL.Name = targetName
	target.Store.AttachmentsPath = filepath.Join(root, "target-attachments")
	target.TLS.ACMEDir = filepath.Join(root, "target-acme")
	if err := os.MkdirAll(target.TLS.ACMEDir, 0700); err != nil {
		t.Fatal(err)
	}
	// DROP is restricted to exact generated names, never a configured database.
	t.Cleanup(func() {
		if fixedDB != "" {
			return // The fixed database is cleaned by the earlier scoped cleanup.
		}
		for _, name := range []string{sourceName, targetName} {
			if !created[name] {
				continue
			}
			conn, err := sql.Open("mysql", mysqlDSN(base.Store.MySQL))
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
	if fixedDB != "" {
		mutated, err := store.OpenConfig(source.Store)
		if err != nil {
			t.Fatal(err)
		}
		_, err = mutated.CreateDomain(&store.Domain{Domain: "after-backup.invalid", IsActive: true})
		mutated.Close()
		if err != nil {
			t.Fatal(err)
		}
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
	if err := CheckRestoreJournal(targetConfigPath); err != nil {
		t.Fatalf("successful MySQL restore retained incomplete marker: %v", err)
	}
	restoredConfig, err := config.Load(targetConfigPath)
	if err != nil {
		t.Fatalf("loading restored config: %v", err)
	}
	if restoredConfig.Store.MySQL.Name != targetName || restoredConfig.Store.AttachmentsPath != target.Store.AttachmentsPath || restoredConfig.TLS.ACMEDir != target.TLS.ACMEDir {
		t.Fatalf("restored config points outside target: database=%q attachments=%q acme=%q", restoredConfig.Store.MySQL.Name, restoredConfig.Store.AttachmentsPath, restoredConfig.TLS.ACMEDir)
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

func mysqlDSN(cfg config.MySQLConfig) string {
	driverCfg := mysql.NewConfig()
	driverCfg.User = cfg.User
	driverCfg.Passwd = cfg.Password
	driverCfg.Net = "tcp"
	driverCfg.Addr = net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port))
	return driverCfg.FormatDSN()
}

func mysqlDBDSN(cfg config.MySQLConfig) string {
	driverCfg := mysql.NewConfig()
	driverCfg.User = cfg.User
	driverCfg.Passwd = cfg.Password
	driverCfg.Net = "tcp"
	driverCfg.Addr = net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port))
	driverCfg.DBName = cfg.Name
	return driverCfg.FormatDSN()
}
