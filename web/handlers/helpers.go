package handlers

import (
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"golang.org/x/net/idna"

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

// encodeHeaderValue encodes unstructured non-ASCII values as RFC 2047 words.
func encodeHeaderValue(value string) string {
	// Header values must never be allowed to create additional fields.
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	// Check if value contains non-ASCII characters
	for _, r := range value {
		if r > 127 {
			// Contains non-ASCII: encode with RFC 2047
			return mime.BEncoding.Encode("UTF-8", value)
		}
	}
	// All ASCII: return as-is
	return value
}

// formatUnstructuredHeader folds at word boundaries without changing the
// decoded value. An indivisible overlong token is rejected at queue admission.
func formatUnstructuredHeader(name, value string) string {
	value = encodeHeaderValue(value)
	var b strings.Builder
	b.WriteString(name)
	b.WriteString(": ")
	lineLength := len(name) + 2
	for i, word := range strings.Fields(value) {
		if i > 0 {
			if lineLength+1+len(word) > 78 {
				b.WriteString("\r\n ")
				lineLength = 1
			} else {
				b.WriteByte(' ')
				lineLength++
			}
		}
		b.WriteString(word)
		lineLength += len(word)
	}
	b.WriteString("\r\n")
	return b.String()
}

// formatRecipientHeader preserves addr-spec syntax. RFC 2047 encoded-words
// belong in display names, never in the mailbox address itself.
func formatRecipientHeader(value string) (string, error) {
	if strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("recipient header contains a line break")
	}
	addresses, err := mail.ParseAddressList(strings.ReplaceAll(value, ";", ","))
	if err != nil {
		return "", err
	}
	formatted := make([]string, 0, len(addresses))
	for _, address := range addresses {
		address.Address = asciiMailboxDomain(address.Address)
		if !isASCII(address.Address) {
			// RFC 6532 keeps an internationalized addr-spec as UTF-8;
			// encoding it as an RFC 2047 word would hide the address.
			if address.Name == "" {
				formatted = append(formatted, address.Address)
			} else {
				formatted = append(formatted, mime.QEncoding.Encode("utf-8", address.Name)+" <"+address.Address+">")
			}
			continue
		}
		formatted = append(formatted, address.String())
	}
	return strings.Join(formatted, ", "), nil
}

func formatLegacyAddressHeader(value string) string {
	if address, err := mail.ParseAddress(value); err == nil && address.Address == value {
		return value
	}
	formatted, err := formatRecipientHeader(value)
	if err == nil {
		return formatted
	}
	// Legacy metadata can predate strict address parsing. Never encode its
	// entire addr-spec as an RFC 2047 word or permit header injection.
	return singleLineHeaderValue(value)
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}

func originatingHeaders(strip bool, clientIP, hostname, messageID string, recipients []string, date time.Time) string {
	hostname = singleLineHeaderValue(hostname)
	messageID = singleLineHeaderValue(messageID)
	clientIP = singleLineHeaderValue(clientIP)
	// RFC 5321 permits exactly one path in the optional FOR clause. Omitting
	// it for multiple recipients also avoids disclosing blind recipients.
	forClause := ""
	if len(recipients) == 1 {
		forClause = fmt.Sprintf("\r\n\tfor <%s>", singleLineHeaderValue(asciiMailboxDomain(recipients[0])))
	}
	var headers strings.Builder
	if strip {
		fmt.Fprintf(&headers, "Received: from webmail\r\n\tby %s with HTTP (GoMail)\r\n\tid %s%s;\r\n\t%s\r\n",
			hostname, messageID, forClause, date.Format(time.RFC1123Z))
	} else {
		fmt.Fprintf(&headers, "Received: from webmail (%s)\r\n\tby %s with HTTP (GoMail)\r\n\tid %s%s;\r\n\t%s\r\n",
			clientIP, hostname, messageID, forClause, date.Format(time.RFC1123Z))
		fmt.Fprintf(&headers, "X-Originating-IP: [%s]\r\n", clientIP)
	}
	return headers.String()
}

// ASCII local parts can use an IDNA A-label in headers and trace fields,
// avoiding an unnecessary SMTPUTF8 requirement on legacy delivery hops.
// Internationalized local parts remain untouched and still require SMTPUTF8.
func asciiMailboxDomain(address string) string {
	at := strings.LastIndexByte(address, '@')
	if at < 0 || !isASCII(address[:at]) || isASCII(address[at+1:]) {
		return address
	}
	domain, err := idna.Lookup.ToASCII(address[at+1:])
	if err != nil || domain == "" {
		return address
	}
	return address[:at+1] + strings.ToLower(domain)
}

func singleLineHeaderValue(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " ")
}
