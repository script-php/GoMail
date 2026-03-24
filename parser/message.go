package parser

import (
	"bytes"
	"fmt"
	"io"
	"net/mail"
	"strings"
	"time"
)

// ParsedMessage holds the parsed components of an RFC 5322 message.
type ParsedMessage struct {
	MessageID   string
	From        string
	To          string
	Cc          string
	ReplyTo     string
	Subject     string
	Date        time.Time
	TextBody    string
	HTMLBody    string
	RawHeaders  string
	Attachments []ParsedAttachment
	Headers     mail.Header
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
		Headers:   msg.Header,
		MessageID: cleanMessageID(msg.Header.Get("Message-ID")),
		From:      msg.Header.Get("From"),
		To:        msg.Header.Get("To"),
		Cc:        msg.Header.Get("Cc"),
		ReplyTo:   msg.Header.Get("Reply-To"),
		Subject:   msg.Header.Get("Subject"),
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

	// Check Content-Type for MIME multipart
	contentType := msg.Header.Get("Content-Type")
	if strings.Contains(contentType, "multipart/") {
		if err := parseMIME(parsed, contentType, body); err != nil {
			// Fallback: treat as plain text
			parsed.TextBody = string(body)
		}
	} else if strings.Contains(contentType, "text/html") {
		parsed.HTMLBody = string(body)
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
