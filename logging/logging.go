package logging

import (
	"log"
	"strings"
)

// Log level constants
const (
	LevelDebug = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	// CurrentLevel is the global log level (default to Info)
	CurrentLevel = LevelInfo

	// levelNames maps level constants to string names
	levelNames = map[int]string{
		LevelDebug: "DEBUG",
		LevelInfo:  "INFO",
		LevelWarn:  "WARN",
		LevelError: "ERROR",
	}

	// nameToLevel maps string names to level constants
	nameToLevel = map[string]int{
		"debug": LevelDebug,
		"info":  LevelInfo,
		"warn":  LevelWarn,
		"error": LevelError,
	}
)

// ParseLevel converts a string level name to a level constant
// Returns LevelInfo (default) if the level is not recognized
func ParseLevel(levelStr string) int {
	if levelStr == "" {
		return LevelInfo // Default
	}

	level, ok := nameToLevel[strings.ToLower(levelStr)]
	if !ok {
		return LevelInfo // Default if not recognized
	}
	return level
}

// Debug logs at DEBUG level
func Debug(format string, v ...interface{}) {
	if CurrentLevel <= LevelDebug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// Info logs at INFO level
func Info(format string, v ...interface{}) {
	if CurrentLevel <= LevelInfo {
		log.Printf("[INFO] "+format, v...)
	}
}

// Warn logs at WARN level
func Warn(format string, v ...interface{}) {
	if CurrentLevel <= LevelWarn {
		log.Printf("[WARN] "+format, v...)
	}
}

// Error logs at ERROR level
func Error(format string, v ...interface{}) {
	if CurrentLevel <= LevelError {
		log.Printf("[ERROR] "+format, v...)
	}
}

// LogAt logs at the specified level
func LogAt(level int, format string, v ...interface{}) {
	if CurrentLevel <= level {
		levelName := levelNames[level]
		log.Printf("["+levelName+"] "+format, v...)
	}
}

// GetLevelName returns the name of a log level
func GetLevelName(level int) string {
	if name, ok := levelNames[level]; ok {
		return name
	}
	return "UNKNOWN"
}
