package handlers

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"gomail/config"
	"gomail/delivery"
	"gomail/security"
	"gomail/store"
	"gomail/templates"
)

// ForwardHandler handles email forwarding.
type ForwardHandler struct {
	cfg        *config.Config
	db         *store.DB
	queue      *delivery.Queue
	sessionMgr *security.SessionManager
	templates  *template.Template
}

// NewForwardHandler creates a forward handler.
func NewForwardHandler(cfg *config.Config, db *store.DB, queue *delivery.Queue, sm *security.SessionManager) *ForwardHandler {
	funcMap := template.FuncMap{
		"safeHTML": func(s string) template.HTML {
			return template.HTML(sanitizeHTML(s))
		},
	}
	tmpl := templates.LoadTemplate(funcMap, "base", "forward", "welcome")

	return &ForwardHandler{
		cfg:        cfg,
		db:         db,
		queue:      queue,
		sessionMgr: sm,
		templates:  tmpl,
	}
}

// ForwardPage shows the forward form for a message.
func (h *ForwardHandler) ForwardPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Extract message ID from URL path: /forward/{messageID}
	msgIDStr := strings.TrimPrefix(r.URL.Path, "/forward/")
	if msgIDStr == "" || msgIDStr == r.URL.Path {
		http.Error(w, "Message ID required", http.StatusBadRequest)
		return
	}

	var msgID int64
	if _, err := fmt.Sscanf(msgIDStr, "%d", &msgID); err != nil {
		http.Error(w, "Invalid message ID", http.StatusBadRequest)
		return
	}

	// Get the original message
	originalMsg, err := h.db.GetMessage(msgID, account.ID)
	if err != nil {
		log.Printf("[forward] error getting message %d: %v", msgID, err)
		http.Error(w, "Message not found", http.StatusNotFound)
		return
	}

	if originalMsg == nil {
		http.Error(w, "Message not found", http.StatusNotFound)
		return
	}

	h.renderForwardForm(w, r, account, originalMsg, "", "", "", "", "", http.StatusOK)
}

func (h *ForwardHandler) renderForwardForm(w http.ResponseWriter, r *http.Request, account *store.Account, originalMsg *store.Message, errorMessage, to, cc, subject, notes string, status int) {
	if subject == "" {
		subject = forwardSubject(originalMsg.Subject)
	}
	folders, _ := h.db.ListFolders(account.ID)
	data := map[string]interface{}{
		"Section":         "forward",
		"OriginalMsg":     originalMsg,
		"OriginalFrom":    originalMsg.FromAddr,
		"OriginalTo":      originalMsg.ToAddr,
		"OriginalCC":      originalMsg.CcAddr,
		"OriginalSubject": subject,
		"OriginalText":    originalMsg.TextBody,
		"OriginalHTML":    originalMsg.HTMLBody,
		"IsHTML":          originalMsg.HTMLBody != "",
		"Account":         account,
		"CSRFToken":       h.sessionMgr.GenerateCSRFToken(r),
		"Folders":         folders,
		"Error":           errorMessage,
		"To":              to,
		"CC":              cc,
		"ForwardNotes":    notes,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[forward] template error: %v", err)
	}
}

// Send processes the forward form and enqueues the message.
func (h *ForwardHandler) Send(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.sessionMgr.ValidateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	msgIDStr := r.FormValue("original_message_id")
	to := r.FormValue("to")
	cc := r.FormValue("cc")
	subject := strings.TrimSpace(r.FormValue("subject"))
	forwardNotes := r.FormValue("forward_notes")

	if msgIDStr == "" || to == "" || subject == "" {
		http.Error(w, "Message ID, recipient, and subject are required", http.StatusBadRequest)
		return
	}

	var msgID int64
	if _, err := fmt.Sscanf(msgIDStr, "%d", &msgID); err != nil {
		http.Error(w, "Invalid message ID", http.StatusBadRequest)
		return
	}

	// Get the original message
	originalMsg, err := h.db.GetMessage(msgID, account.ID)
	if err != nil {
		log.Printf("[forward] error getting message %d: %v", msgID, err)
		http.Error(w, "Message not found", http.StatusNotFound)
		return
	}

	if originalMsg == nil {
		http.Error(w, "Message not found", http.StatusNotFound)
		return
	}

	log.Printf("[forward.Send] retrieved original message: id=%d, direction=%s, rawmsg_size=%d",
		originalMsg.ID, originalMsg.Direction, len(originalMsg.RawMessage))

	// Parse recipients
	recipients := parseRecipients(to)
	if cc != "" {
		recipients = append(recipients, parseRecipients(cc)...)
	}

	if len(recipients) == 0 {
		http.Error(w, "No valid recipients", http.StatusBadRequest)
		return
	}

	// Validate local recipients exist before enqueuing
	localDomains, _ := h.db.ListAllDomainNames()
	for _, rcpt := range recipients {
		parts := strings.SplitN(rcpt, "@", 2)
		if len(parts) != 2 {
			continue
		}
		rcptDomain := strings.ToLower(parts[1])
		isLocal := false
		for _, d := range localDomains {
			if strings.EqualFold(d, rcptDomain) {
				isLocal = true
				break
			}
		}
		if isLocal {
			acct, err := h.db.GetAccountByEmail(rcpt)
			if err != nil || acct == nil || !acct.IsActive {
				http.Error(w, fmt.Sprintf("Recipient not found: %s", rcpt), http.StatusBadRequest)
				return
			}
		}
	}

	from := account.Email
	msgID2 := fmt.Sprintf("<%d@%s>", time.Now().UnixNano(), account.DomainName)
	clientIP := getRealClientIP(r)

	// Build forwarded message
	var msg strings.Builder

	msg.WriteString(originatingHeaders(h.cfg.Mail.StripOriginatingIP, clientIP, h.cfg.Server.Hostname, msgID2, to, time.Now()))

	// Add Resent- headers (RFC 5322 forwarding convention)
	// These encode non-ASCII characters if present
	msg.WriteString(fmt.Sprintf("Resent-From: %s\r\n", encodeHeaderValue(from)))
	msg.WriteString(fmt.Sprintf("Resent-Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	msg.WriteString(fmt.Sprintf("Resent-To: %s\r\n", encodeHeaderValue(to)))
	if cc != "" {
		msg.WriteString(fmt.Sprintf("Resent-Cc: %s\r\n", encodeHeaderValue(cc)))
	}
	msg.WriteString(fmt.Sprintf("Resent-Message-ID: %s\r\n", msgID2))

	// For forwarded messages, From: must be the forwarder for DMARC alignment with DKIM signature.
	// Original sender goes in Reply-To for context. Resent- headers also identify the forwarder.
	msg.WriteString(fmt.Sprintf("From: %s\r\n", encodeHeaderValue(from)))
	msg.WriteString(fmt.Sprintf("Reply-To: %s\r\n", encodeHeaderValue(originalMsg.FromAddr)))

	// Use the actual forward recipient, not the original message's recipient
	msg.WriteString(fmt.Sprintf("To: %s\r\n", encodeHeaderValue(to)))
	if cc != "" {
		msg.WriteString(fmt.Sprintf("Cc: %s\r\n", encodeHeaderValue(cc)))
	}
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", encodeHeaderValue(subject)))
	msg.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))

	// Message-ID for the wrapper message (not the original)
	// Use msgID2 which was generated for this wrapper message
	msg.WriteString(fmt.Sprintf("Message-ID: %s\r\n", msgID2))

	// User agent
	msg.WriteString(fmt.Sprintf("User-Agent: %s\r\n", config.UserAgent()))

	// Generate boundary for multipart message
	boundary := fmt.Sprintf("boundary_%d", time.Now().UnixNano())

	// Build MIME structure: message/rfc822 wrapper to preserve original completely
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))
	msg.WriteString("\r\n")

	// Part 1 is always a normal text body. Some clients hide message/rfc822 parts,
	// so include a readable copy of the original message here as well.
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("Content-Disposition: inline\r\n")
	msg.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	msg.WriteString("\r\n")
	if forwardNotes != "" {
		msg.WriteString(normalizeBodyLineEndings(forwardNotes))
		msg.WriteString("\r\n\r\n")
	}
	msg.WriteString("---------- Forwarded message ----------\r\n")
	msg.WriteString("From: " + singleLineBodyValue(originalMsg.FromAddr) + "\r\n")
	msg.WriteString("Date: " + originalMsg.ReceivedAt.Format(time.RFC1123Z) + "\r\n")
	msg.WriteString("Subject: " + singleLineBodyValue(originalMsg.Subject) + "\r\n")
	msg.WriteString("To: " + singleLineBodyValue(originalMsg.ToAddr) + "\r\n")
	if originalMsg.CcAddr != "" {
		msg.WriteString("Cc: " + singleLineBodyValue(originalMsg.CcAddr) + "\r\n")
	}
	msg.WriteString("\r\n")
	if originalMsg.TextBody != "" {
		msg.WriteString(normalizeBodyLineEndings(originalMsg.TextBody))
	} else if originalMsg.HTMLBody != "" {
		msg.WriteString("[The original message contains HTML content. See the attached original message.]\r\n")
	}
	msg.WriteString("\r\n")

	// Part 2 attaches the complete source message. RawMessage preserves the
	// original MIME structure, headers, and attachments.
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: message/rfc822; name=\"forwarded-message.eml\"\r\n")
	msg.WriteString("Content-Disposition: attachment; filename=\"forwarded-message.eml\"\r\n")
	msg.WriteString("\r\n")
	if len(originalMsg.RawMessage) > 0 {
		msg.WriteString(normalizeBodyLineEndings(string(originalMsg.RawMessage)))
	} else {
		msg.WriteString(buildForwardedRFC822(originalMsg))
	}
	msg.WriteString("\r\n")

	// End of multipart
	msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	messageToEnqueue := []byte(msg.String())
	log.Printf("[forward.Send] final wrapper message size=%d", len(messageToEnqueue))

	// Enqueue for delivery
	if err := h.queue.Enqueue(from, recipients, messageToEnqueue, account.ID); err != nil {
		log.Printf("[forward] enqueue error: %v", err)
		message := "The message could not be queued. Please try again."
		if strings.Contains(err.Error(), "DKIM") || strings.Contains(err.Error(), "unsigned delivery") {
			message = "Forwarding is unavailable because DKIM is not configured for your sender domain. An administrator must open Admin → Domains, edit the domain, and generate DKIM keys."
		}
		h.renderForwardForm(w, r, account, originalMsg, message, to, cc, subject, forwardNotes, http.StatusUnprocessableEntity)
		return
	}

	log.Printf("[forward] message forwarded from=%s to=%v msgID=%d", from, recipients, msgID)
	http.Redirect(w, r, "/message/"+msgIDStr, http.StatusSeeOther)
}

func forwardSubject(subject string) string {
	subject = strings.TrimSpace(subject)
	if strings.HasPrefix(strings.ToLower(subject), "fwd:") {
		return subject
	}
	return "Fwd: " + subject
}

func normalizeBodyLineEndings(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strings.ReplaceAll(value, "\n", "\r\n")
}

func singleLineBodyValue(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.ReplaceAll(value, "\n", " ")
}

// buildForwardedRFC822 provides a valid fallback for legacy messages whose raw
// source was not retained. Newer messages use RawMessage above.
func buildForwardedRFC822(originalMsg *store.Message) string {

	var rfc822Message strings.Builder

	// Essential headers only (From, To, Cc, Date, Subject, Message-ID, Reply-To)
	rfc822Message.WriteString("From: " + encodeHeaderValue(originalMsg.FromAddr) + "\r\n")
	rfc822Message.WriteString("To: " + encodeHeaderValue(originalMsg.ToAddr) + "\r\n")
	if originalMsg.CcAddr != "" {
		rfc822Message.WriteString("Cc: " + encodeHeaderValue(originalMsg.CcAddr) + "\r\n")
	}
	if originalMsg.ReplyTo != "" {
		rfc822Message.WriteString("Reply-To: " + encodeHeaderValue(originalMsg.ReplyTo) + "\r\n")
	}
	rfc822Message.WriteString("Date: " + originalMsg.ReceivedAt.Format(time.RFC1123Z) + "\r\n")
	rfc822Message.WriteString("Subject: " + encodeHeaderValue(originalMsg.Subject) + "\r\n")

	// Message-ID must be wrapped in angle brackets per RFC 5322
	messageID := originalMsg.MessageID
	if messageID != "" && !strings.HasPrefix(messageID, "<") {
		messageID = "<" + messageID + ">"
	}
	rfc822Message.WriteString("Message-ID: " + messageID + "\r\n")

	// MIME headers for the body
	rfc822Message.WriteString("MIME-Version: 1.0\r\n")

	// Include both HTML and text if available
	if originalMsg.HTMLBody != "" {
		// Create multipart/alternative for HTML + text
		bodyBoundary := fmt.Sprintf("boundary_%d", time.Now().UnixNano())
		rfc822Message.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", bodyBoundary))
		rfc822Message.WriteString("\r\n")

		// Text part
		rfc822Message.WriteString(fmt.Sprintf("--%s\r\n", bodyBoundary))
		rfc822Message.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		rfc822Message.WriteString("\r\n")
		rfc822Message.WriteString(normalizeBodyLineEndings(originalMsg.TextBody))
		rfc822Message.WriteString("\r\n")

		// HTML part
		rfc822Message.WriteString(fmt.Sprintf("--%s\r\n", bodyBoundary))
		rfc822Message.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		rfc822Message.WriteString("\r\n")
		rfc822Message.WriteString(sanitizeHTML(originalMsg.HTMLBody))
		rfc822Message.WriteString(fmt.Sprintf("\r\n--%s--\r\n", bodyBoundary))
	} else {
		// Plain text only
		rfc822Message.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		rfc822Message.WriteString("\r\n")
		rfc822Message.WriteString(normalizeBodyLineEndings(originalMsg.TextBody))
	}
	return rfc822Message.String()
}

// escapeHTML escapes text for safe HTML inclusion.
func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

// extractHeaderValue extracts a single header value from raw headers string.
// Returns empty string if header not found. Handles folded headers (continuation lines).
func extractHeaderValue(rawHeaders, headerName string) string {
	if rawHeaders == "" {
		return ""
	}

	// Case-insensitive search for the header
	headerNameLower := strings.ToLower(headerName)
	lines := strings.Split(rawHeaders, "\r\n")

	for i, line := range lines {
		if line == "" {
			break // End of headers
		}

		// Split on first ':'
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		if strings.ToLower(strings.TrimSpace(parts[0])) == headerNameLower {
			value := strings.TrimSpace(parts[1])

			// Handle continuation lines (RFC 5322 header folding)
			// Continued lines start with space or tab
			for i+1 < len(lines) && len(lines[i+1]) > 0 {
				nextLine := lines[i+1]
				if nextLine[0] != ' ' && nextLine[0] != '\t' {
					break
				}
				value += " " + strings.TrimSpace(nextLine)
				i++
			}

			return value
		}
	}

	return ""
}
