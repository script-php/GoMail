package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gomail/config"
	"gomail/delivery"
	"gomail/mdn"
	"gomail/security"
	"gomail/store"
	"gomail/templates"
)

// MessageHandler handles viewing individual messages.
type MessageHandler struct {
	db         *store.DB
	cfg        *config.Config
	queue      *delivery.Queue
	sessionMgr *security.SessionManager
	templates  *template.Template
}

// NewMessageHandler creates a message handler.
func NewMessageHandler(cfg *config.Config, db *store.DB, queue *delivery.Queue, sm *security.SessionManager) *MessageHandler {
	funcMap := template.FuncMap{
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
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

	tmpl := templates.LoadTemplate(funcMap, "base", "message")

	return &MessageHandler{
		db:         db,
		cfg:        cfg,
		queue:      queue,
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

	log.Printf("[web] View message: id=%d, MDNRequested=%v, MDNAddress=%s, MDNSent=%v, Config.MDN.Enabled=%s, Config.MDN.Mode=%s",
		id, msg.MDNRequested, msg.MDNAddress, msg.MDNSent, h.cfg.MDN.Enabled, h.cfg.MDN.Mode)

	// Mark as read
	if !msg.IsRead {
		h.db.MarkRead(id)
		msg.IsRead = true
		
		// Update folder counts since message is now read
		if msg.FolderID != nil {
			h.db.UpdateFolderCounts(*msg.FolderID)
		}

		// Handle MDN (Message Disposition Notification) if requested
		if msg.MDNRequested && !msg.MDNSent && h.cfg.MDN.Enabled == "yes" {
			log.Printf("[web] MDN handling - mode=%s, address=%s", h.cfg.MDN.Mode, msg.MDNAddress)
			h.handleMDN(msg, account)
		}
	}

	// Get attachments
	attachments, _ := h.db.GetAttachments(id)

	unread, _ := h.db.CountUnread(account.ID)
	folders, _ := h.db.ListFolders(account.ID)

	data := map[string]interface{}{
		"Title":       msg.Subject,
		"Message":     msg,
		"Attachments": attachments,
		"Unread":      unread,
		"CSRFToken":   h.sessionMgr.GenerateCSRFToken(r),
		"Section":     msg.Direction,
		"Account":     account,
		"Folders":     folders,
		"MDNMode":     h.cfg.MDN.Mode,
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

// handleMDN handles Message Disposition Notification based on config mode
func (h *MessageHandler) handleMDN(msg *store.Message, account *store.Account) {
	if msg.MDNAddress == "" {
		log.Printf("[web] handleMDN: no MDN address")
		return
	}

	log.Printf("[web] handleMDN: mode=%s, checking auto mode", h.cfg.MDN.Mode)
	// In auto mode, send MDN immediately
	if h.cfg.MDN.Mode == "auto" {
		log.Printf("[web] handleMDN: sending MDN in auto mode")
		h.sendMDN(msg, account)
	} else {
		log.Printf("[web] handleMDN: manual mode, no auto-send")
	}
	// In manual mode, MDN will be shown in template and user can send/deny via API
}

// sendMDN generates and sends an MDN response
func (h *MessageHandler) sendMDN(msg *store.Message, account *store.Account) {
	log.Printf("[web] sendMDN: starting for msg=%d, recipient=%s", msg.ID, msg.MDNAddress)
	// Generate MDN message
	mdnBody := mdn.GenerateMDN(
		msg.MessageID,
		msg.Subject,
		account.Email,
		msg.MDNAddress,
		h.cfg.Server.Hostname,
	)

	log.Printf("[web] sendMDN: MDN body generated, enqueueing for delivery")
	// Enqueue MDN for delivery
	if err := h.queue.Enqueue(account.Email, []string{msg.MDNAddress}, []byte(mdnBody), account.ID); err != nil {
		log.Printf("[web] MDN enqueue error: %v", err)
		return
	}

	// Mark MDN as sent
	h.db.MarkMDNSent(msg.ID)
	log.Printf("[web] MDN sent for message %d to %s", msg.ID, msg.MDNAddress)
}

// SendMDN handles the API endpoint for manually sending MDN
func (h *MessageHandler) SendMDN(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/api/send-mdn/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid message ID", http.StatusBadRequest)
		return
	}

	msg, err := h.db.GetMessage(id, account.ID)
	if err != nil || msg == nil {
		http.Error(w, "Message not found", http.StatusNotFound)
		return
	}

	if !msg.MDNRequested {
		http.Error(w, "No MDN requested for this message", http.StatusBadRequest)
		return
	}

	if msg.MDNSent {
		http.Error(w, "MDN already sent", http.StatusBadRequest)
		return
	}

	log.Printf("[web] SendMDN API: sending MDN for message %d", id)
	h.sendMDN(msg, account)

	// Redirect back to the message
	http.Redirect(w, r, "/message/"+idStr, http.StatusSeeOther)
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
