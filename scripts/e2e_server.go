//go:build ignore

// Command e2e_server starts a disposable GoMail web instance for Playwright.
package main

import (
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	backupops "gomail/backup"
	"gomail/config"
	"gomail/delivery"
	"gomail/store"
	"gomail/web"
)

func main() {
	root, err := os.MkdirTemp("", "gomail-e2e-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(root)

	tlsEnabled := false
	cfg := &config.Config{}
	cfg.Server.Hostname = "mail.example.test"
	cfg.Server.Domain = "example.test"
	cfg.Store.Database = "sqlite"
	cfg.Store.DBPath = filepath.Join(root, "mail.db")
	cfg.Store.AttachmentsPath = filepath.Join(root, "attachments")
	cfg.Web.EnableTLS = &tlsEnabled
	cfg.Web.HTTPAddr = "127.0.0.1:18080"
	cfg.Web.SessionMaxAge = 3600
	cfg.Web.SessionSecret = "browser-test-session-secret"
	cfg.Web.RateLimitPerMin = 10000
	cfg.Security.CSRFKey = "browser-test-csrf-key"
	cfg.DKIM.KeysDir = filepath.Join(root, "keys")
	cfg.TLS.ACMEDir = filepath.Join(root, "acme")

	db, err := store.Open(cfg.Store.DBPath, cfg.Store.AttachmentsPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		log.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("browser-test-password"), bcrypt.MinCost)
	if err != nil {
		log.Fatal(err)
	}
	accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "admin@example.test", DisplayName: "Admin", PasswordHash: string(hash), IsAdmin: true, IsActive: true})
	if err != nil {
		log.Fatal(err)
	}
	inbox, err := db.GetFolderByType(accountID, "inbox")
	if err != nil || inbox == nil {
		log.Fatalf("loading inbox: %v", err)
	}
	_, err = db.SaveMessage(&store.Message{AccountID: accountID, FolderID: &inbox.ID, MessageID: "browser-fixture@example.test", Direction: "inbound", FromAddr: "sender@example.net", ToAddr: "admin@example.test", Subject: "Browser fixture message", TextBody: "This message drives browser interaction coverage.", RawMessage: []byte("Subject: Browser fixture message\r\n\r\nThis message drives browser interaction coverage."), Size: 96, ReceivedAt: time.Now().UTC()})
	if err != nil {
		log.Fatal(err)
	}
	for _, browser := range []string{"chromium", "firefox", "webkit"} {
		for _, state := range []string{"pending", "failed"} {
			id, queueErr := db.EnqueueMessage(&store.QueueEntry{MailFrom: "admin@example.test", RcptTo: state + "-" + browser + "@browser.invalid", RawMessage: []byte("From: admin@example.test\r\n\r\nBrowser queue fixture"), MaxAttempts: 6, NextRetry: time.Now().Add(time.Hour)})
			if queueErr != nil { log.Fatal(queueErr) }
			if state == "failed" {
				if _, queueErr = db.Exec(`UPDATE outbound_queue SET status = 'failed', attempts = 1, last_error = 'browser fixture failure' WHERE id = ?`, id); queueErr != nil { log.Fatal(queueErr) }
			}
		}
	}
	configPath := filepath.Join(root, "config.json")
	encoded, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(configPath, encoded, 0600); err != nil {
		log.Fatal(err)
	}
	manager := backupops.NewManager(cfg, db, configPath, "e2e")
	server := web.NewServer(cfg, db, delivery.NewQueue(db, cfg), nil, manager)
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Printf("e2e server stopped: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	_ = server.Shutdown()
}
