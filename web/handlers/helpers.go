package handlers

import (
	"encoding/base64"
	"fmt"
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
// It checks (in order): X-Forwarded-For, X-Real-IP, CF-Connecting-IP, then falls back to RemoteAddr.
// X-Forwarded-For can contain multiple IPs (comma-separated), so we take the first (leftmost).
func getRealClientIP(r *http.Request) string {
	// Check X-Forwarded-For (most common, used by nginx, Apache, load balancers)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For format: "client, proxy1, proxy2"
		// The leftmost IP is the client's real IP
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			if ip := strings.TrimSpace(ips[0]); ip != "" {
				return ip
			}
		}
	}

	// Check X-Real-IP (used by nginx)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Check CF-Connecting-IP (Cloudflare)
	if cfip := r.Header.Get("CF-Connecting-IP"); cfip != "" {
		return cfip
	}

	// Fallback to direct connection IP
	// Remove port if present (e.g., "192.0.2.1:54321" -> "192.0.2.1")
	clientAddr := r.RemoteAddr
	if idx := strings.LastIndex(clientAddr, ":"); idx >= 0 {
		clientAddr = clientAddr[:idx]
	}
	return clientAddr
}

// encodeHeaderValue encodes a header value using RFC 2047 if it contains non-ASCII characters
// Format: =?UTF-8?B?base64_encoded_value?=
func encodeHeaderValue(value string) string {
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
