package parser

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"time"
)

// ParsedMessage holds the parsed components of an RFC 5322 message.
type ParsedMessage struct {
	MessageID      string
	From           string
	To             string
	Cc             string
	ReplyTo        string
	Subject        string
	Date           time.Time
	TextBody       string
	HTMLBody       string
	RawHeaders     string
	Attachments    []ParsedAttachment
	Headers        mail.Header
	MDNRequestedBy string // Disposition-Notification-To address
}

// ParsedAttachment holds a decoded attachment from a MIME message.
type ParsedAttachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

// Parse takes raw email bytes and returns a ParsedMessage.
func Parse(raw []byte) (*ParsedMessage, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parsing message: %w", err)
	}

	parsed := &ParsedMessage{
		Headers:        msg.Header,
		MessageID:      cleanMessageID(msg.Header.Get("Message-ID")),
		From:           msg.Header.Get("From"),
		To:             msg.Header.Get("To"),
		Cc:             msg.Header.Get("Cc"),
		ReplyTo:        msg.Header.Get("Reply-To"),
		Subject:        decodeRFC2047(msg.Header.Get("Subject")),
		MDNRequestedBy: cleanAddress(msg.Header.Get("Disposition-Notification-To")),
	}

	// Parse date
	if dateStr := msg.Header.Get("Date"); dateStr != "" {
		if t, err := mail.ParseDate(dateStr); err == nil {
			parsed.Date = t
		}
	}
	if parsed.Date.IsZero() {
		parsed.Date = time.Now()
	}

	// Build raw headers string
	var headerBuf strings.Builder
	for key, values := range msg.Header {
		for _, v := range values {
			headerBuf.WriteString(key)
			headerBuf.WriteString(": ")
			headerBuf.WriteString(v)
			headerBuf.WriteString("\r\n")
		}
	}
	parsed.RawHeaders = headerBuf.String()

	// Read body
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, fmt.Errorf("reading message body: %w", err)
	}

	// Decode transfer encoding (base64, quoted-printable)
	body = decodeTransferEncoding(body, msg.Header.Get("Content-Transfer-Encoding"))

	// Check Content-Type for MIME multipart
	contentType := msg.Header.Get("Content-Type")
	if strings.Contains(contentType, "multipart/") {
		if err := parseMIME(parsed, contentType, body); err != nil {
			// Fallback: treat as plain text
			parsed.TextBody = string(body)
		}
	} else if strings.Contains(contentType, "text/html") {
		// Store HTML but also provide as text for display
		parsed.HTMLBody = string(body)
		parsed.TextBody = strings.TrimSpace(htmlToPlainText(string(body)))
		if parsed.TextBody == "" {
			parsed.TextBody = string(body) // If conversion fails, use HTML as-is
		}
	} else {
		// Plain text or unknown
		parsed.TextBody = string(body)
	}

	return parsed, nil
}

// cleanAddress extracts email address from angle brackets or returns as-is.
func cleanAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	if idx := strings.LastIndex(addr, "<"); idx >= 0 {
		if end := strings.Index(addr[idx:], ">"); end >= 0 {
			return addr[idx+1 : idx+end]
		}
	}
	return addr
}

// cleanMessageID strips angle brackets from Message-ID.
func cleanMessageID(id string) string {
	id = strings.TrimSpace(id)
	id = strings.TrimPrefix(id, "<")
	id = strings.TrimSuffix(id, ">")
	return id
}

// decodeRFC2047 decodes RFC 2047 encoded-word format (e.g., =?UTF-8?B?...?=)
func decodeRFC2047(s string) string {
	if !strings.Contains(s, "=?") {
		return s // Not encoded
	}

	// Use Go's mime package for proper RFC 2047 decoding
	decoder := mime.WordDecoder{}
	result, err := decoder.DecodeHeader(s)
	if err == nil {
		return result
	}

	// Fallback: simple regex-based attempt
	re := regexp.MustCompile(`=\?([^?]+)\?([BbQq])\?([^?]+)\?=`)
	return re.ReplaceAllStringFunc(s, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) != 4 {
			return match
		}

		// parts[1] is charset (not used - assume UTF-8)
		encoding := strings.ToUpper(parts[2])
		data := parts[3]

		var decoded []byte
		var err error

		if encoding == "B" {
			decoded, err = base64.StdEncoding.DecodeString(data)
		} else if encoding == "Q" {
			// Quoted-printable, replace _ with space
			data = strings.ReplaceAll(data, "_", " ")
			buf := new(bytes.Buffer)
			_, err = io.Copy(buf, quotedprintable.NewReader(strings.NewReader(data)))
			decoded = buf.Bytes()
		}

		if err != nil {
			return match
		}

		// For now, assume UTF-8 (most modern emails use it)
		return string(decoded)
	})
}

// decodeTransferEncoding handles base64 and quoted-printable encoding
func decodeTransferEncoding(data []byte, encoding string) []byte {
	encoding = strings.ToLower(strings.TrimSpace(encoding))

	if strings.Contains(encoding, "base64") {
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err == nil {
			return decoded
		}
		return data
	}

	if strings.Contains(encoding, "quoted-printable") {
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, quotedprintable.NewReader(bytes.NewReader(data))); err == nil {
			return buf.Bytes()
		}
		return data
	}

	// 7bit, 8bit, binary - no decoding needed
	return data
}

// htmlToPlainText strips HTML tags, keeping only text content
func htmlToPlainText(html string) string {
	// Remove HTML tags
	re := regexp.MustCompile(`<[^>]+>`)
	text := re.ReplaceAllString(html, "")

	// Decode HTML entities
	text = strings.ReplaceAll(text, "&nbsp;", " ")
	text = strings.ReplaceAll(text, "&lt;", "<")
	text = strings.ReplaceAll(text, "&gt;", ">")
	text = strings.ReplaceAll(text, "&amp;", "&")
	text = strings.ReplaceAll(text, "&quot;", "\"")

	// Clean up multiple spaces and newlines
	text = regexp.MustCompile(`\n\s*\n`).ReplaceAllString(text, "\n\n")
	text = strings.TrimSpace(text)

	return text
}
