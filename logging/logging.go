package logging

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	LevelDebug = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	CurrentLevel  = LevelInfo
	CurrentFormat = "text"
	levelNames    = map[int]string{LevelDebug: "DEBUG", LevelInfo: "INFO", LevelWarn: "WARN", LevelError: "ERROR"}
	nameToLevel   = map[string]int{"debug": LevelDebug, "info": LevelInfo, "warn": LevelWarn, "error": LevelError}
	outputMu      sync.Mutex
	logger        = log.New(os.Stderr, "", log.LstdFlags)
	emailPattern  = regexp.MustCompile(`(?i)[a-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-z0-9.-]+`)
	ipv4Pattern   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

func Configure(level, format string) {
	outputMu.Lock()
	defer outputMu.Unlock()
	CurrentLevel = ParseLevel(level)
	CurrentFormat = strings.ToLower(strings.TrimSpace(format))
	if CurrentFormat == "" {
		CurrentFormat = "text"
	}
	if CurrentFormat == "json" {
		logger.SetFlags(0)
	} else {
		logger.SetFlags(log.LstdFlags)
	}
	log.SetFlags(0)
	log.SetOutput(standardLogBridge{})
}

func SetOutput(writer io.Writer) {
	outputMu.Lock()
	defer outputMu.Unlock()
	logger.SetOutput(writer)
}

func ParseLevel(level string) int {
	if parsed, ok := nameToLevel[strings.ToLower(strings.TrimSpace(level))]; ok {
		return parsed
	}
	return LevelInfo
}

func Debug(message string) { logAt(LevelDebug, message) }
func Info(message string)  { logAt(LevelInfo, message) }
func Warn(message string)  { logAt(LevelWarn, message) }
func Error(message string) { logAt(LevelError, message) }
func LogAt(level int, message string) {
	logAt(level, message)
}

func logAt(level int, message string) {
	outputMu.Lock()
	defer outputMu.Unlock()
	if CurrentLevel > level {
		return
	}
	component, message := splitComponent(redactMessage(message))
	levelName := GetLevelName(level)
	if CurrentFormat == "json" {
		record := struct {
			Timestamp string `json:"timestamp"`
			Level     string `json:"level"`
			Component string `json:"component,omitempty"`
			Message   string `json:"message"`
		}{time.Now().UTC().Format(time.RFC3339Nano), strings.ToLower(levelName), component, message}
		encoded, _ := json.Marshal(record)
		logger.Print(string(encoded))
		return
	}
	if component != "" {
		message = "[" + component + "] " + message
	}
	logger.Printf("[%s] %s", levelName, message)
}

type standardLogBridge struct{}

func (standardLogBridge) Write(data []byte) (int, error) {
	message := strings.TrimSpace(string(data))
	level := LevelInfo
	lower := strings.ToLower(message)
	if strings.Contains(lower, "error") || strings.Contains(lower, "failed") || strings.Contains(lower, "failure") {
		level = LevelError
	} else if strings.Contains(lower, "warning") || strings.Contains(lower, "invalid") {
		level = LevelWarn
	}
	logAt(level, message)
	return len(data), nil
}

func redactMessage(message string) string {
	message = emailPattern.ReplaceAllString(message, "<email>")
	return ipv4Pattern.ReplaceAllString(message, "<ip>")
}

func splitComponent(message string) (string, string) {
	if !strings.HasPrefix(message, "[") {
		return "", message
	}
	end := strings.IndexByte(message, ']')
	if end < 2 || end > 33 {
		return "", message
	}
	component := message[1:end]
	for _, char := range component {
		if !(char == '-' || char == '_' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
			return "", message
		}
	}
	return strings.ToLower(component), strings.TrimSpace(message[end+1:])
}

func GetLevelName(level int) string {
	if name, ok := levelNames[level]; ok {
		return name
	}
	return "UNKNOWN"
}
