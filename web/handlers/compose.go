package handlers

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"gomail/config"
	"gomail/delivery"
	"gomail/security"
	"gomail/store"
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
	tmpl := template.Must(template.ParseFiles(
		filepath.Join("web", "templates", "base.html"),
		filepath.Join("web", "templates", "compose.html"),
	))

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
	unread, _ := h.db.CountUnread()

	// Check for reply
	replyTo := r.URL.Query().Get("reply")
	var prefill map[string]string
	if replyTo != "" {
		// Load original message for reply
		// (simplified: just set To and Subject)
		prefill = map[string]string{
			"to":      r.URL.Query().Get("to"),
			"subject": r.URL.Query().Get("subject"),
		}
	}

	data := map[string]interface{}{
		"Title":     "Compose",
		"From":      h.cfg.Server.AdminEmail,
		"Unread":    unread,
		"CSRFToken": h.sessionMgr.GenerateCSRFToken(r),
		"Section":   "compose",
		"Prefill":   prefill,
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

	to := r.FormValue("to")
	cc := r.FormValue("cc")
	subject := r.FormValue("subject")
	body := r.FormValue("body")

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

	// Build the RFC 5322 message
	from := h.cfg.Server.AdminEmail
	msgID := fmt.Sprintf("<%d@%s>", time.Now().UnixNano(), h.cfg.Server.Domain)

	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("From: %s\r\n", from))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	if cc != "" {
		msg.WriteString(fmt.Sprintf("Cc: %s\r\n", cc))
	}
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	msg.WriteString(fmt.Sprintf("Message-ID: %s\r\n", msgID))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)

	// Enqueue for delivery
	if err := h.queue.Enqueue(from, recipients, []byte(msg.String())); err != nil {
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
