package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func editableConfig() *Config {
	return &Config{Server: ServerConfig{Hostname: "mail.example.com"}, Store: StoreConfig{MySQL: MySQLConfig{Password: "db-secret-value"}}, Web: WebConfig{SessionSecret: "session-secret-value", BootstrapAdmin: BootstrapAdmin{PasswordHash: "bootstrap-secret-value"}}, Security: SecurityConfig{CSRFKey: "csrf-secret-value"}, Metrics: MetricsConfig{BearerToken: "metrics-secret-value"}}
}

func TestEditableJSONPreservesHiddenSecrets(t *testing.T) {
	current := editableConfig()
	data, err := EditableJSON(current)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"db-secret-value", "session-secret-value", "bootstrap-secret-value", "csrf-secret-value", "metrics-secret-value"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("editable JSON exposed %q", secret)
		}
	}
	candidate, err := ParseEditableJSON(data, current)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Store.MySQL.Password != "db-secret-value" || candidate.Web.SessionSecret != "session-secret-value" || candidate.Security.CSRFKey != "csrf-secret-value" || candidate.Metrics.BearerToken != "metrics-secret-value" {
		t.Fatal("secret placeholder did not preserve current values")
	}
}

func TestSaveAtomicCreatesBackupAndValidConfig(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.json")
	if err := os.WriteFile(path, []byte(`{"server":{"hostname":"old.example"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := editableConfig()
	backup, err := SaveAtomic(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.Server.Hostname != "mail.example.com" {
		t.Fatalf("saved configuration invalid: %+v %v", loaded, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("configuration mode = %o", info.Mode().Perm())
	}
}

func TestRestartRequiredClassification(t *testing.T) {
	running := editableConfig()
	saved := *running
	saved.Logging.Level = "debug"
	if RestartRequired(running, &saved) {
		t.Fatal("logging-only change should apply live")
	}
	saved.SMTP.ListenAddr = ":2525"
	if !RestartRequired(running, &saved) {
		t.Fatal("listener change must require restart")
	}
}

func TestEditableJSONRejectsUnknownFields(t *testing.T) {
	_, err := ParseEditableJSON([]byte(`{"server":{"hostname":"mail.example.com"},"unknown":true}`), editableConfig())
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown configuration field accepted: %v", err)
	}
}
