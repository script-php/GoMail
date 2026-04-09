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

// ComposeHandler handles composing and sending messages.
type ComposeHandler struct {
	cfg        *config.Config
	db         *store.DB
	queue      *delivery.Queue
	sessionMgr *security.SessionManager
	templates  *template.Template
}

// NewComposeHandler creates a compose handler.
func NewComposeHandler(cfg *config.Config, db *store.DB, queue *delivery.Queue, sm *security.SessionManager) *ComposeHandler {
	funcMap := template.FuncMap{}
	tmpl := templates.LoadTemplate(funcMap, "base", "compose", "welcome")

	return &ComposeHandler{
		cfg:        cfg,
		db:         db,
		queue:      queue,
		sessionMgr: sm,
		templates:  tmpl,
	}
}

// ComposePage shows the compose form.
func (h *ComposeHandler) ComposePage(w http.ResponseWriter, r *http.Request) {
	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	unread, _ := h.db.CountUnread(account.ID)
	folders, _ := h.db.ListFolders(account.ID)

	// Check for reply
	replyTo := r.URL.Query().Get("reply")
	var prefill map[string]string
	if replyTo != "" {
		prefill = map[string]string{
			"to":      r.URL.Query().Get("to"),
			"subject": r.URL.Query().Get("subject"),
		}
	}

	data := map[string]interface{}{
		"Title":     "Compose",
		"From":      account.Email,
		"Unread":    unread,
		"CSRFToken": h.sessionMgr.GenerateCSRFToken(r),
		"Section":   "compose",
		"Prefill":   prefill,
		"Account":   account,
		"Folders":   folders,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[web] template error: %v", err)
	}
}

// Send processes the compose form and enqueues the message.
func (h *ComposeHandler) Send(w http.ResponseWriter, r *http.Request) {
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

	to := r.FormValue("to")
	cc := r.FormValue("cc")
	subject := r.FormValue("subject")
	body := r.FormValue("body")
	priority := r.FormValue("priority")
	readReceipt := r.FormValue("read_receipt") == "1"
	if priority == "" {
		priority = "3" // Default to Normal
	}

	if to == "" || subject == "" || body == "" {
		http.Error(w, "To, Subject, and Body are required", http.StatusBadRequest)
		return
	}

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
	var validationErrors []string

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
				validationErrors = append(validationErrors, fmt.Sprintf("Recipient not found: %s", rcpt))
			}
		}
	}

	// If there are validation errors, re-render compose form with errors
	if len(validationErrors) > 0 {
		folders, _ := h.db.ListFolders(account.ID)
		unread, _ := h.db.CountUnread(account.ID)

		data := map[string]interface{}{
			"Title":     "Compose",
			"From":      account.Email,
			"Unread":    unread,
			"CSRFToken": h.sessionMgr.GenerateCSRFToken(r),
			"Section":   "compose",
			"Account":   account,
			"Folders":   folders,
			"Error":     strings.Join(validationErrors, "; "),
			"Prefill": map[string]string{
				"to":       to,
				"cc":       cc,
				"subject":  subject,
				"body":     body,
				"priority": priority,
			},
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
			log.Printf("[web] template error: %v", err)
		}
		return
	}

	// Build the RFC 5322 message
	from := account.Email
	msgID := fmt.Sprintf("<%d@%s>", time.Now().UnixNano(), account.DomainName)

	// Extract real client IP (handles reverse proxies: nginx, Cloudflare, etc.)
	clientIP := getRealClientIP(r)

	var msg strings.Builder

	// Build Received header - show IP only if explicitly enabled
	var receivedLine string
	if h.cfg.Mail.StripOriginatingIP {
		receivedLine = fmt.Sprintf("Received: from webmail (%s)\r\n\tby %s with HTTP (GoMail)\r\n\tid %s\r\n\tfor <%s>;\r\n\t%s",
			clientIP,
			h.cfg.Server.Hostname,
			msgID,
			to,
			time.Now().Format(time.RFC1123Z),
		)
	} else {
		receivedLine = fmt.Sprintf("Received: from webmail\r\n\tby %s with HTTP (GoMail)\r\n\tid %s\r\n\tfor <%s>;\r\n\t%s",
			h.cfg.Server.Hostname,
			msgID,
			to,
			time.Now().Format(time.RFC1123Z),
		)
	}
	msg.WriteString(receivedLine + "\r\n")
	msg.WriteString(fmt.Sprintf("From: %s\r\n", from))
	msg.WriteString(fmt.Sprintf("Return-Path: <%s>\r\n", from))

	// Include X-Originating-IP only if explicitly enabled
	if h.cfg.Mail.StripOriginatingIP {
		msg.WriteString(fmt.Sprintf("X-Originating-IP: [%s]\r\n", clientIP))
	}

	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	if cc != "" {
		msg.WriteString(fmt.Sprintf("Cc: %s\r\n", cc))
	}
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	msg.WriteString(fmt.Sprintf("Message-ID: %s\r\n", msgID))
	msg.WriteString(fmt.Sprintf("User-Agent: %s\r\n", config.UserAgent()))
	msg.WriteString(fmt.Sprintf("X-Priority: %s\r\n", priority))
	msg.WriteString(fmt.Sprintf("Priority: %s\r\n", priorityToText(priority)))
	msg.WriteString(fmt.Sprintf("Importance: %s\r\n", priorityToImportance(priority)))
	if readReceipt {
		msg.WriteString(fmt.Sprintf("Disposition-Notification-To: %s\r\n", from))
	}

	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)

	// Enqueue for delivery (queue handles per-domain DKIM signing)
	if err := h.queue.Enqueue(from, recipients, []byte(msg.String()), account.ID); err != nil {
		log.Printf("[web] enqueue error: %v", err)
		http.Error(w, "Failed to send message", http.StatusInternalServerError)
		return
	}

	log.Printf("[web] message enqueued from=%s to=%v subject=%s", from, recipients, subject)
	http.Redirect(w, r, "/sent", http.StatusSeeOther)
}

// parseRecipients splits a comma/semicolon-separated list of email addresses.
func parseRecipients(s string) []string {
	s = strings.ReplaceAll(s, ";", ",")
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		// Extract from "Name <email>" format
		if idx := strings.LastIndex(p, "<"); idx >= 0 {
			end := strings.Index(p[idx:], ">")
			if end > 0 {
				p = p[idx+1 : idx+end]
			}
		}
		if p != "" && strings.Contains(p, "@") {
			result = append(result, p)
		}
	}
	return result
}

// priorityToText converts X-Priority numeric value to RFC 2156 Priority text value
func priorityToText(xPriority string) string {
	switch xPriority {
	case "1", "2":
		return "urgent"
	case "3":
		return "normal"
	case "4", "5":
		return "non-urgent"
	default:
		return "normal" // Default to normal
	}
}

// priorityToImportance converts X-Priority numeric value to RFC 2156 Importance header value
func priorityToImportance(xPriority string) string {
	switch xPriority {
	case "1", "2":
		return "high"
	case "3":
		return "normal"
	case "4", "5":
		return "low"
	default:
		return "normal" // Default to normal
	}
}
