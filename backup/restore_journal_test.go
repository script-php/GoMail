package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gomail/config"
	"gomail/store"
)

func TestCompleteDurableRestoreVerifiesActiveSnapshot(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	cfg := &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test"}, TLS: config.TLSConfig{Mode: "none", ACMEDir: filepath.Join(root, "acme")}, Store: config.StoreConfig{Database: "sqlite", DBPath: filepath.Join(root, "mail.db"), AttachmentsPath: filepath.Join(root, "attachments")}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.TLS.ACMEDir, 0700); err != nil {
		t.Fatal(err)
	}
	acmeFile := filepath.Join(cfg.TLS.ACMEDir, "account.key")
	if err := os.WriteFile(acmeFile, []byte("original ACME material"), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenConfig(cfg.Store)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "backup.tar.gz")
	if _, err := Create(cfg, configPath, archive, "test"); err != nil {
		t.Fatal(err)
	}
	safety := filepath.Join(root, "safety.tar.gz")
	if _, err := Create(cfg, configPath, safety, "test"); err != nil {
		t.Fatal(err)
	}
	if err := beginRestoreJournal(configPath, archive, safety); err != nil {
		t.Fatal(err)
	}
	if done, err := CompleteDurableRestore(configPath); err != nil || done {
		t.Fatalf("non-durable marker was completed: %v %v", done, err)
	}
	if err := updateRestoreJournalPhase(configPath, "durable"); err != nil {
		t.Fatal(err)
	}
	if done, err := CompleteDurableRestore(configPath); err != nil || !done {
		t.Fatalf("matching durable marker was not completed: %v %v", done, err)
	}
	if err := CheckRestoreJournal(configPath); err != nil {
		t.Fatal(err)
	}
	configRecord, err := hashFile("config/config.json", configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := beginRestoreJournal(configPath, archive, safety, "", "", "", "", configRecord.SHA256); err != nil {
		t.Fatal(err)
	}
	if err := updateRestoreJournalPhase(configPath, "durable"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, append(append([]byte{}, encoded...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if done, err := CompleteDurableRestore(configPath); err == nil || done || !strings.Contains(err.Error(), "staged configuration") {
		t.Fatalf("changed staged config accepted: done=%v err=%v", done, err)
	}
	if err := CheckRestoreJournal(configPath); err == nil {
		t.Fatal("changed staged configuration removed restore marker")
	}
	if err := os.WriteFile(configPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if done, err := CompleteDurableRestore(configPath); err != nil || !done {
		t.Fatalf("restored staged config rejected: done=%v err=%v", done, err)
	}
	if err := beginRestoreJournal(configPath, archive, safety); err != nil {
		t.Fatal(err)
	}
	if err := updateRestoreJournalPhase(configPath, "durable"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(acmeFile, []byte("changed ACME material"), 0600); err != nil {
		t.Fatal(err)
	}
	if done, err := CompleteDurableRestore(configPath); err == nil || done || !strings.Contains(err.Error(), "acme/") {
		t.Fatalf("changed ACME material accepted: done=%v err=%v", done, err)
	}
	if err := os.WriteFile(acmeFile, []byte("original ACME material"), 0600); err != nil {
		t.Fatal(err)
	}
	if done, err := CompleteDurableRestore(configPath); err != nil || !done {
		t.Fatalf("restored ACME material rejected: done=%v err=%v", done, err)
	}
	if err := beginRestoreJournal(configPath, archive, safety); err != nil {
		t.Fatal(err)
	}
	if err := updateRestoreJournalPhase(configPath, "durable"); err != nil {
		t.Fatal(err)
	}
	staleACME := filepath.Join(cfg.TLS.ACMEDir, "stale.key")
	if err := os.WriteFile(staleACME, []byte("old credential"), 0600); err != nil {
		t.Fatal(err)
	}
	if done, err := CompleteDurableRestore(configPath); err == nil || done || !strings.Contains(err.Error(), "acme/stale.key") {
		t.Fatalf("unarchived ACME credential accepted: done=%v err=%v", done, err)
	}
	if err := CheckRestoreJournal(configPath); err == nil {
		t.Fatal("unarchived ACME credential removed restore marker")
	}
	if err := os.Remove(staleACME); err != nil {
		t.Fatal(err)
	}
	if done, err := CompleteDurableRestore(configPath); err != nil || !done {
		t.Fatalf("clean ACME tree rejected: done=%v err=%v", done, err)
	}
	if err := beginRestoreJournal(configPath, archive, safety); err != nil {
		t.Fatal(err)
	}
	if err := updateRestoreJournalPhase(configPath, "durable"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, append(append([]byte{}, encoded...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if done, err := CompleteDurableRestore(configPath); err == nil || done || !strings.Contains(err.Error(), "config/config.json") {
		t.Fatalf("changed restored config accepted: done=%v err=%v", done, err)
	}
	if err := os.WriteFile(configPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if done, err := CompleteDurableRestore(configPath); err != nil || !done {
		t.Fatalf("restored config rejected: done=%v err=%v", done, err)
	}
	if err := beginRestoreJournal(configPath, archive, safety); err != nil {
		t.Fatal(err)
	}
	if err := updateRestoreJournalPhase(configPath, "durable"); err != nil {
		t.Fatal(err)
	}
	db, err = store.OpenConfig(cfg.Store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateDomain(&store.Domain{Domain: "changed.example", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if done, err := CompleteDurableRestore(configPath); err == nil || done {
		t.Fatalf("changed active snapshot was accepted: %v %v", done, err)
	}
	if err := CheckRestoreJournal(configPath); err == nil {
		t.Fatal("failed verification removed restore marker")
	}
}

func TestCompleteDurableRestoreRequiresValidSafetyArchive(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	cfg := &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test"}, TLS: config.TLSConfig{Mode: "none"}, Store: config.StoreConfig{Database: "sqlite", DBPath: filepath.Join(root, "mail.db"), AttachmentsPath: filepath.Join(root, "attachments")}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenConfig(cfg.Store)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "backup.tar.gz")
	if _, err := Create(cfg, configPath, archive, "test"); err != nil {
		t.Fatal(err)
	}
	safety := filepath.Join(root, "safety.tar.gz")
	if err := os.WriteFile(safety, []byte("corrupt safety archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := beginRestoreJournal(configPath, archive, safety); err != nil {
		t.Fatal(err)
	}
	if err := updateRestoreJournalPhase(configPath, "durable"); err != nil {
		t.Fatal(err)
	}
	if done, err := CompleteDurableRestore(configPath); err == nil || done || !strings.Contains(err.Error(), "safety archive") {
		t.Fatalf("corrupt safety archive accepted: done=%v err=%v", done, err)
	}
	if err := CheckRestoreJournal(configPath); err == nil {
		t.Fatal("failed verification removed restore marker")
	}
}

func TestCompleteDurableRestoreRejectsChangedTLSKey(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	keyPath := filepath.Join(root, "private-key.pem")
	certPath := filepath.Join(root, "certificate.pem")
	cfg := &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test"}, TLS: config.TLSConfig{Mode: "manual", CertFile: certPath, KeyFile: keyPath}, Store: config.StoreConfig{Database: "sqlite", DBPath: filepath.Join(root, "mail.db"), AttachmentsPath: filepath.Join(root, "attachments")}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{configPath: string(encoded), keyPath: "original private key", certPath: "original certificate"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	db, err := store.OpenConfig(cfg.Store)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "backup.tar.gz")
	if _, err := Create(cfg, configPath, archive, "test"); err != nil {
		t.Fatal(err)
	}
	if err := beginRestoreJournal(configPath, archive, archive); err != nil {
		t.Fatal(err)
	}
	if err := updateRestoreJournalPhase(configPath, "durable"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("changed private key"), 0600); err != nil {
		t.Fatal(err)
	}
	if done, err := CompleteDurableRestore(configPath); err == nil || done || !strings.Contains(err.Error(), "tls/private-key.pem") {
		t.Fatalf("changed TLS key accepted: done=%v err=%v", done, err)
	}
	if err := CheckRestoreJournal(configPath); err == nil {
		t.Fatal("changed TLS key cleared restore marker")
	}
}

func TestRestoreJournalBlocksStartupUntilOperatorRecovery(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := CheckRestoreJournal(configPath); err != nil {
		t.Fatal(err)
	}
	if err := beginRestoreJournal(configPath, "requested.tar.gz", "safety.tar.gz"); err != nil {
		t.Fatal(err)
	}
	if err := updateRestoreJournalPhase(configPath, "attachments_activated"); err != nil {
		t.Fatal(err)
	}
	marker := restoreJournalPath(configPath)
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	var entry restoreJournal
	if err := json.Unmarshal(data, &entry); err != nil || filepath.Base(entry.Archive) != "requested.tar.gz" || filepath.Base(entry.SafetyArchive) != "safety.tar.gz" || entry.Phase != "attachments_activated" || entry.UpdatedAt.IsZero() {
		t.Fatalf("restore marker has no recovery pointers: %+v, %v", entry, err)
	}
	if info, err := os.Stat(marker); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("marker permissions: %v, %v", info, err)
	}
	if err := CheckRestoreJournal(configPath); err == nil || !strings.Contains(err.Error(), "incomplete restore") || !strings.Contains(err.Error(), "attachments_activated") {
		t.Fatalf("startup accepted incomplete restore: %v", err)
	}
	if err := beginRestoreJournal(configPath, "second.tar.gz", "second-safety.tar.gz"); err == nil {
		t.Fatal("second restore overwrote unresolved marker")
	}
	if err := finishRestoreJournal(configPath); err != nil {
		t.Fatal(err)
	}
	if err := CheckRestoreJournal(configPath); err != nil {
		t.Fatal(err)
	}
	if err := beginRestoreJournal(configPath, "requested.tar.gz", "safety.tar.gz", "active", "stage", "/old/attachments", "/old/acme"); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(restoreJournalPath(configPath))
	if err != nil {
		t.Fatal(err)
	}
	var staged restoreJournal
	if err := json.Unmarshal(data, &staged); err != nil || staged.ActiveDatabase != "active" || staged.StagingDatabase != "stage" || staged.PreviousAttachments != "/old/attachments" || staged.PreviousACME != "/old/acme" {
		t.Fatalf("staged database identities missing from recovery marker: %+v %v", staged, err)
	}
	if err := finishRestoreJournal(configPath); err != nil {
		t.Fatal(err)
	}
}
