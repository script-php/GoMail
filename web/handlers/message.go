package handlers

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gomail/security"
	"gomail/store"
)

// MessageHandler handles viewing individual messages.
type MessageHandler struct {
	db         *store.DB
	sessionMgr *security.SessionManager
	templates  *template.Template
}

// NewMessageHandler creates a message handler.
func NewMessageHandler(db *store.DB, sm *security.SessionManager) *MessageHandler {
	funcMap := template.FuncMap{
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
		"formatAuth": func(result string) string {
			switch result {
			case "pass":
				return "✓ Pass"
			case "fail":
				return "✗ Fail"
			default:
				return "— " + result
			}
		},
		"authClass": func(result string) string {
			switch result {
			case "pass":
				return "auth-pass"
			case "fail":
				return "auth-fail"
			default:
				return "auth-neutral"
			}
		},
	}

	tmpl := template.Must(template.New("").Funcs(funcMap).ParseFiles(
		filepath.Join("web", "templates", "base.html"),
		filepath.Join("web", "templates", "message.html"),
	))

	return &MessageHandler{
		db:         db,
		sessionMgr: sm,
		templates:  tmpl,
	}
}

// View shows a single message.
func (h *MessageHandler) View(w http.ResponseWriter, r *http.Request) {
	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/message/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	msg, err := h.db.GetMessage(id, account.ID)
	if err != nil || msg == nil {
		http.NotFound(w, r)
		return
	}

	// Mark as read
	if !msg.IsRead {
		h.db.MarkRead(id)
		msg.IsRead = true
	}

	// Get attachments
	attachments, _ := h.db.GetAttachments(id)

	unread, _ := h.db.CountUnread(account.ID)

	data := map[string]interface{}{
		"Title":       msg.Subject,
		"Message":     msg,
		"Attachments": attachments,
		"Unread":      unread,
		"CSRFToken":   h.sessionMgr.GenerateCSRFToken(r),
		"Section":     msg.Direction,
		"Account":     account,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[web] template error: %v", err)
	}
}

// Delete soft-deletes a message.
func (h *MessageHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.sessionMgr.ValidateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/message/delete/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	h.db.DeleteMessage(id)
	http.Redirect(w, r, "/inbox", http.StatusSeeOther)
}

// ToggleStar toggles the starred status.
func (h *MessageHandler) ToggleStar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/message/star/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	msg, err := h.db.GetMessage(id, account.ID)
	if err != nil || msg == nil {
		http.NotFound(w, r)
		return
	}

	h.db.MarkStarred(id, !msg.IsStarred)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"starred": !msg.IsStarred})
}

// MarkRead marks a message as read (AJAX).
func (h *MessageHandler) MarkRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/api/mark-read/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	h.db.MarkRead(id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// DownloadAttachment serves an attachment file.
func (h *MessageHandler) DownloadAttachment(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/attachment/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Find the attachment
	// We need to look it up — for simplicity, query by attachment ID
	var att store.Attachment
	err = h.db.QueryRow(`
		SELECT id, message_id, filename, content_type, size, storage_path
		FROM attachments WHERE id = ?`, id).Scan(
		&att.ID, &att.MessageID, &att.Filename, &att.ContentType, &att.Size, &att.StoragePath,
	)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	fullPath := filepath.Join(h.db.AttachmentsPath(), att.StoragePath)

	// Check file exists
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", att.ContentType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+att.Filename+"\"")
	http.ServeFile(w, r, fullPath)
}
