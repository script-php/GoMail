package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"strconv"

	"gomail/security"
	"gomail/store"
)

// InboxHandler handles inbox and sent message listing.
type InboxHandler struct {
	db         *store.DB
	sessionMgr *security.SessionManager
	templates  *template.Template
}

// NewInboxHandler creates an inbox handler.
func NewInboxHandler(db *store.DB, sm *security.SessionManager) *InboxHandler {
	funcMap := template.FuncMap{
		"truncate": func(s string, n int) string {
			if len(s) > n {
				return s[:n] + "..."
			}
			return s
		},
		"formatSize": func(size int64) string {
			switch {
			case size >= 1048576:
				return fmt.Sprintf("%.1f MB", float64(size)/1048576)
			case size >= 1024:
				return fmt.Sprintf("%.1f KB", float64(size)/1024)
			default:
				return fmt.Sprintf("%d B", size)
			}
		},
		"add": func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
	}

	tmpl := template.Must(template.New("").Funcs(funcMap).ParseFiles(
		filepath.Join("web", "templates", "base.html"),
		filepath.Join("web", "templates", "inbox.html"),
	))

	return &InboxHandler{
		db:         db,
		sessionMgr: sm,
		templates:  tmpl,
	}
}

// Inbox shows the inbox (inbound messages).
func (h *InboxHandler) Inbox(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage := 50

	messages, err := h.db.ListMessages("inbound", perPage, (page-1)*perPage)
	if err != nil {
		log.Printf("[web] inbox list error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	total, _ := h.db.CountMessages("inbound")
	unread, _ := h.db.CountUnread()

	data := map[string]interface{}{
		"Title":      "Inbox",
		"Messages":   messages,
		"Page":       page,
		"TotalPages": (total + perPage - 1) / perPage,
		"Total":      total,
		"Unread":     unread,
		"CSRFToken":  h.sessionMgr.GenerateCSRFToken(r),
		"Section":    "inbox",
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[web] template error: %v", err)
	}
}

// Sent shows the sent (outbound) messages.
func (h *InboxHandler) Sent(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage := 50

	messages, err := h.db.ListMessages("outbound", perPage, (page-1)*perPage)
	if err != nil {
		log.Printf("[web] sent list error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	total, _ := h.db.CountMessages("outbound")
	unread, _ := h.db.CountUnread()

	data := map[string]interface{}{
		"Title":      "Sent",
		"Messages":   messages,
		"Page":       page,
		"TotalPages": (total + perPage - 1) / perPage,
		"Total":      total,
		"Unread":     unread,
		"CSRFToken":  h.sessionMgr.GenerateCSRFToken(r),
		"Section":    "sent",
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[web] template error: %v", err)
	}
}

// UnreadCount returns the unread count as JSON (for AJAX polling).
func (h *InboxHandler) UnreadCount(w http.ResponseWriter, r *http.Request) {
	count, _ := h.db.CountUnread()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"unread": count})
}
