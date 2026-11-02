package handlers

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"gomail/security"
	"gomail/store"
)

// getSessionAccount returns the authenticated account for the current request.
// Returns nil if not logged in or account not found.
func getSessionAccount(db *store.DB, sm *security.SessionManager, r *http.Request) *store.Account {
	email := sm.GetSession(r)
	if email == "" {
		return nil
	}
	account, _ := db.GetAccountByEmail(email)
	return account
}

// getRealClientIP extracts the real client IP address, considering reverse proxies.
// Forwarding headers have already been normalized by TrustedProxyMiddleware.
// Never consult raw provider-specific headers such as CF-Connecting-IP here.
func getRealClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := net.ParseIP(strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])); ip != nil {
			return ip.String()
		}
	}
	if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); ip != nil {
		return ip.String()
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host
}

// encodeHeaderValue encodes a header value using RFC 2047 if it contains non-ASCII characters
// Format: =?UTF-8?B?base64_encoded_value?=
func encodeHeaderValue(value string) string {
	// Header values must never be allowed to create additional fields.
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	// Check if value contains non-ASCII characters
	for _, r := range value {
		if r > 127 {
			// Contains non-ASCII: encode with RFC 2047
			encoded := base64.StdEncoding.EncodeToString([]byte(value))
			return fmt.Sprintf("=?UTF-8?B?%s?=", encoded)
		}
	}
	// All ASCII: return as-is
	return value
}

func originatingHeaders(strip bool, clientIP, hostname, messageID, recipient string, date time.Time) string {
	hostname = singleLineHeaderValue(hostname)
	messageID = singleLineHeaderValue(messageID)
	recipient = singleLineHeaderValue(recipient)
	clientIP = singleLineHeaderValue(clientIP)
	var headers strings.Builder
	if strip {
		fmt.Fprintf(&headers, "Received: from webmail\r\n\tby %s with HTTP (GoMail)\r\n\tid %s\r\n\tfor <%s>;\r\n\t%s\r\n",
			hostname, messageID, recipient, date.Format(time.RFC1123Z))
	} else {
		fmt.Fprintf(&headers, "Received: from webmail (%s)\r\n\tby %s with HTTP (GoMail)\r\n\tid %s\r\n\tfor <%s>;\r\n\t%s\r\n",
			clientIP, hostname, messageID, recipient, date.Format(time.RFC1123Z))
		fmt.Fprintf(&headers, "X-Originating-IP: [%s]\r\n", clientIP)
	}
	return headers.String()
}

func singleLineHeaderValue(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " ")
}
