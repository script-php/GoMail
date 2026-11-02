package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"
)

const SecretPlaceholder = "__KEEP_EXISTING_SECRET__"

// EditableJSON returns the complete configuration while replacing secrets with
// a write-only placeholder. Submitting the placeholder preserves the old value.
func EditableJSON(cfg *Config) ([]byte, error) {
	copy := *cfg
	redactConfigSecrets(&copy)
	return json.MarshalIndent(&copy, "", "  ")
}

// ParseEditableJSON parses and validates an admin-edited configuration. Secret
// placeholders are replaced from the currently persisted configuration.
func ParseEditableJSON(data []byte, current *Config) (*Config, error) {
	var candidate Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&candidate); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple JSON documents")
		}
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	preserveConfigSecrets(&candidate, current)
	if err := candidate.Validate(); err != nil {
		return nil, err
	}
	return &candidate, nil
}

// SaveAtomic writes a validated configuration with restrictive permissions and
// keeps a timestamped copy of the previous file for operator rollback.
func SaveAtomic(path string, cfg *Config) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0750); err != nil {
		return "", err
	}
	old, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading current configuration: %w", err)
	}
	backupPath := path + ".backup-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	if err := os.WriteFile(backupPath, old, 0600); err != nil {
		return "", fmt.Errorf("creating configuration backup: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".gomail-config-*")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return "", err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return "", err
	}
	return backupPath, nil
}

// ChangedSections reports top-level configuration areas without exposing values.
func ChangedSections(before, after *Config) []string {
	beforeValue, afterValue := reflect.ValueOf(*before), reflect.ValueOf(*after)
	typeInfo := beforeValue.Type()
	var changed []string
	for index := 0; index < beforeValue.NumField(); index++ {
		if !reflect.DeepEqual(beforeValue.Field(index).Interface(), afterValue.Field(index).Interface()) {
			name := typeInfo.Field(index).Tag.Get("json")
			changed = append(changed, name)
		}
	}
	sort.Strings(changed)
	return changed
}

// RestartRequired ignores settings that are explicitly applied live.
func RestartRequired(running, saved *Config) bool {
	runningCopy, savedCopy := *running, *saved
	runningCopy.Logging = LoggingConfig{}
	savedCopy.Logging = LoggingConfig{}
	runningCopy.OutboundLimits = OutboundLimitsConfig{}
	savedCopy.OutboundLimits = OutboundLimitsConfig{}
	return !reflect.DeepEqual(runningCopy, savedCopy)
}

func redactConfigSecrets(cfg *Config) {
	cfg.Store.MySQL.Password = SecretPlaceholder
	cfg.Web.SessionSecret = SecretPlaceholder
	cfg.Web.BootstrapAdmin.PasswordHash = SecretPlaceholder
	cfg.Security.CSRFKey = SecretPlaceholder
	cfg.Metrics.BearerToken = SecretPlaceholder
}

func preserveConfigSecrets(candidate, current *Config) {
	if candidate.Store.MySQL.Password == SecretPlaceholder {
		candidate.Store.MySQL.Password = current.Store.MySQL.Password
	}
	if candidate.Web.SessionSecret == SecretPlaceholder {
		candidate.Web.SessionSecret = current.Web.SessionSecret
	}
	if candidate.Web.BootstrapAdmin.PasswordHash == SecretPlaceholder {
		candidate.Web.BootstrapAdmin.PasswordHash = current.Web.BootstrapAdmin.PasswordHash
	}
	if candidate.Security.CSRFKey == SecretPlaceholder {
		candidate.Security.CSRFKey = current.Security.CSRFKey
	}
	if candidate.Metrics.BearerToken == SecretPlaceholder {
		candidate.Metrics.BearerToken = current.Metrics.BearerToken
	}
}
