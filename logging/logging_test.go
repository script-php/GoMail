package logging

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"strings"
	"testing"
)

func TestJSONLoggingExtractsComponent(t *testing.T) {
	var output bytes.Buffer
	SetOutput(&output)
	t.Cleanup(func() { SetOutput(os.Stderr); Configure("info", "text") })
	Configure("debug", "json")
	Info("[smtp] accepted message 7")
	line := output.String()
	start := strings.IndexByte(line, '{')
	if start < 0 {
		t.Fatalf("missing JSON record: %q", line)
	}
	var record map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(line[start:])), &record); err != nil {
		t.Fatal(err)
	}
	if record["level"] != "info" || record["component"] != "smtp" || record["message"] != "accepted message 7" {
		t.Fatalf("unexpected record: %#v", record)
	}
}

func TestStandardLoggerBridgeAndRedaction(t *testing.T) {
	var output bytes.Buffer
	SetOutput(&output)
	t.Cleanup(func() { SetOutput(os.Stderr); Configure("info", "text") })
	Configure("debug", "json")
	log.Printf("[auth] login failed for user@example.com from 192.0.2.4")
	line := output.String()
	if strings.Contains(line, "user@example.com") || strings.Contains(line, "192.0.2.4") {
		t.Fatalf("sensitive address was not redacted: %q", line)
	}
	var record map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &record); err != nil {
		t.Fatal(err)
	}
	if record["component"] != "auth" || record["level"] != "error" || !strings.Contains(record["message"], "<email>") || !strings.Contains(record["message"], "<ip>") {
		t.Fatalf("legacy log was not bridged: %#v", record)
	}
}

func TestLevelFiltering(t *testing.T) {
	var output bytes.Buffer
	SetOutput(&output)
	t.Cleanup(func() { SetOutput(os.Stderr); Configure("info", "text") })
	Configure("warn", "text")
	Info("hidden")
	Warn("visible")
	if strings.Contains(output.String(), "hidden") || !strings.Contains(output.String(), "[WARN] visible") {
		t.Fatalf("unexpected output: %q", output.String())
	}
}
