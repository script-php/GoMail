package delivery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gomail/config"
	"gomail/store"
)

func TestLocalDeliveryDefersWhenAttachmentMetadataFails(t *testing.T) {
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
	if _, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "bob@example.test", PasswordHash: "unused", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_local_attachment BEFORE INSERT ON attachments BEGIN SELECT RAISE(FAIL, 'sidecar unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	raw := strings.Join([]string{
		"From: alice@example.test", "To: bob@example.test", "Subject: attachment", "MIME-Version: 1.0",
		`Content-Type: multipart/mixed; boundary="part"`, "", "--part", "Content-Type: text/plain", "", "hello",
		"--part", "Content-Type: application/octet-stream", `Content-Disposition: attachment; filename="report.txt"`,
		"Content-Transfer-Encoding: base64", "", "cGF5bG9hZA==", "--part--", "",
	}, "\r\n")
	w := &Worker{db: db, cfg: &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test"}}}
	entry := &store.QueueEntry{MailFrom: "alice@example.test", RcptTo: "bob@example.test"}
	if err := w.deliverLocal(entry, []byte(raw)); err == nil || !strings.Contains(err.Error(), "saving attachment") {
		t.Fatalf("expected sidecar metadata failure, got %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages WHERE account_id=1`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("local messages after failure=%d err=%v", count, err)
	}
	files, err := os.ReadDir(db.AttachmentsPath())
	if err != nil || len(files) != 0 {
		t.Fatalf("sidecar files after failure=%d err=%v", len(files), err)
	}
}
