package config

import (
	_ "embed"
	"strings"
)

//go:embed version.txt
var versionFile string

// Version returns the current GoMail version
func Version() string {
	return strings.TrimSpace(versionFile)
}

// UserAgent returns the GoMail User-Agent string
func UserAgent() string {
	return "GoMail/" + Version()
}
