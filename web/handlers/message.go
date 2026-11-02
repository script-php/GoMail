package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"html/template"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gomail/config"
	"gomail/delivery"
	"gomail/mdn"
	"gomail/parser"
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
			return template.HTML(sanitizeHTML(s))
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

	tmpl := templates.LoadTemplate(funcMap, "base", "message", "welcome")

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

	log.Printf("[web] View message: id=%d, subject=%q, textLen=%d, htmlLen=%d",
		id, msg.Subject, len(msg.TextBody), len(msg.HTMLBody))
	log.Printf("[web] View message: id=%d, MDNRequested=%v, MDNAddress=%s, MDNSent=%v, Config.MDN.Enabled=%s, Config.MDN.Mode=%s",
		id, msg.MDNRequested, msg.MDNAddress, msg.MDNSent, h.cfg.MDN.Enabled, h.cfg.MDN.Mode)

	// Mark as read
	if !msg.IsRead {
		if err := h.db.MarkRead(id); err != nil {
			log.Printf("[web] mark message %d read: %v", id, err)
			http.Error(w, "Unable to update message", http.StatusInternalServerError)
			return
		}
		msg.IsRead = true

		// Update folder counts since message is now read
		if msg.FolderID != nil {
			if err := h.db.UpdateFolderCounts(*msg.FolderID); err != nil {
				log.Printf("[web] update folder counts after reading message %d: %v", id, err)
			}
		}

	}
	// A transient enqueue failure must remain retryable on later views, even
	// after the message was marked read on its first view.
	if msg.MDNRequested && !msg.MDNSent && h.cfg.MDN.Enabled == "yes" && h.cfg.MDN.Mode == "auto" {
		if err := h.sendMDN(msg, account); err != nil && !errors.Is(err, store.ErrMDNAlreadySent) {
			log.Printf("[web] automatic MDN enqueue for message %d: %v", id, err)
		}
	}

	// Raw MIME is authoritative. A previous sidecar write may have failed after
	// acceptance; repair it on an account-scoped view instead of hiding it.
	attachments, attachmentErr := h.db.GetAttachments(id)
	if attachmentErr == nil && msg.HasAttachments && len(attachments) == 0 {
		if err := parser.RepairAttachments(h.db, msg, h.db.AttachmentsPath()); err != nil {
			attachmentErr = err
			log.Printf("[web] attachment repair for message %d: %v", id, err)
		} else {
			attachments, attachmentErr = h.db.GetAttachments(id)
		}
	}
	attachmentUnavailable := attachmentErr != nil || (msg.HasAttachments && len(attachments) == 0)

	unread, _ := h.db.CountUnread(account.ID)
	folders, _ := h.db.ListFolders(account.ID)

	data := map[string]interface{}{
		"Title":                 msg.Subject,
		"Message":               msg,
		"Attachments":           attachments,
		"AttachmentUnavailable": attachmentUnavailable,
		"Unread":                unread,
		"CSRFToken":             h.sessionMgr.GenerateCSRFToken(r),
		"Section":               msg.Direction,
		"Account":               account,
		"Folders":               folders,
		"MDNMode":               h.cfg.MDN.Mode,
		"RemoteImages":          h.remoteImagesAllowed(r, account.ID, id),
		"RemoteImagePermit":     h.remoteImagePermit(r, account.ID, id),
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

	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err := h.db.ApplyMessageAction(account.ID, []int64{id}, "trash", 0); err != nil {
		http.Error(w, "Unable to delete message", http.StatusNotFound)
		return
	}
	http.Redirect(w, r, "/inbox", http.StatusSeeOther)
}

// PermanentDelete irreversibly removes a message that is already in Trash.
func (h *MessageHandler) PermanentDelete(w http.ResponseWriter, r *http.Request) {
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
	idText := strings.TrimPrefix(r.URL.Path, "/message/permanent-delete/")
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || h.db.PermanentlyDeleteMessages(account.ID, []int64{id}) != nil {
		http.NotFound(w, r)
		return
	}
	trash, _ := h.db.GetFolderByType(account.ID, "trash")
	if trash != nil {
		http.Redirect(w, r, fmt.Sprintf("/folder/%d", trash.ID), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/inbox", http.StatusSeeOther)
}

// ToggleStar toggles the starred status.
func (h *MessageHandler) ToggleStar(w http.ResponseWriter, r *http.Request) {
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

	if err := h.db.MarkStarred(id, !msg.IsStarred); err != nil {
		http.Error(w, "Unable to update star", http.StatusInternalServerError)
		return
	}

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

	if !h.sessionMgr.ValidateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err := h.db.ApplyMessageAction(account.ID, []int64{id}, "read", 0); err != nil {
		http.Error(w, "Unable to mark message read", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// sendMDN generates and sends an MDN response
func (h *MessageHandler) sendMDN(msg *store.Message, account *store.Account) error {
	if msg.MDNAddress == "" {
		return fmt.Errorf("MDN destination is empty")
	}
	log.Printf("[web] sendMDN: starting for msg=%d, recipient=%s", msg.ID, msg.MDNAddress)
	// Generate MDN message using multipart/report format per RFC 3798
	mdnBody := mdn.GenerateMDNMultipart(
		msg.MessageID,
		msg.Subject,
		account.Email,
		msg.MDNAddress,
		h.cfg.Server.Hostname,
	)

	log.Printf("[web] sendMDN: MDN body generated, enqueueing for delivery")
	// Enqueue MDN for delivery
	if err := h.queue.EnqueueMDN(account.Email, []string{msg.MDNAddress}, []byte(mdnBody), account.ID, msg.ID); err != nil {
		log.Printf("[web] MDN enqueue error: %v", err)
		return err
	}

	msg.MDNSent = true
	log.Printf("[web] MDN sent for message %d to %s", msg.ID, msg.MDNAddress)
	return nil
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
	if err := h.sendMDN(msg, account); err != nil {
		if errors.Is(err, store.ErrMDNAlreadySent) {
			http.Error(w, "MDN already sent", http.StatusConflict)
		} else {
			http.Error(w, "Unable to queue MDN; please retry", http.StatusServiceUnavailable)
		}
		return
	}

	// Redirect back to the message
	http.Redirect(w, r, "/message/"+idStr, http.StatusSeeOther)
}

// DownloadAttachment serves an attachment file.
func (h *MessageHandler) DownloadAttachment(w http.ResponseWriter, r *http.Request) {
	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/attachment/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	att, err := h.db.GetAttachmentForAccount(id, account.ID)
	if err != nil || att == nil {
		http.NotFound(w, r)
		return
	}

	name := att.StoragePath
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		http.NotFound(w, r)
		return
	}
	// Open relative to a trusted directory descriptor. O_NOFOLLOW prevents a
	// replaced attachment filename from escaping the tree, even during a race.
	baseFD, err := unix.Open(h.db.AttachmentsPath(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer unix.Close(baseFD)
	fileFD, err := unix.Openat(baseFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	file := os.NewFile(uintptr(fileFD), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}

	contentType := att.ContentType
	if _, _, err := mime.ParseMediaType(contentType); err != nil {
		contentType = "application/octet-stream"
	}
	disposition := mime.FormatMediaType("attachment", map[string]string{"filename": filepath.Base(att.Filename)})
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", disposition)
	http.ServeContent(w, r, filepath.Base(att.Filename), info.ModTime(), file)
}

// Content serves sanitized HTML mail in a sandboxed, origin-isolated frame.
func (h *MessageHandler) Content(w http.ResponseWriter, r *http.Request) {
	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	idText := strings.TrimPrefix(r.URL.Path, "/message-content/")
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	msg, err := h.db.GetMessage(id, account.ID)
	if err != nil || msg == nil || msg.HTMLBody == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	allowRemote := h.remoteImagesAllowed(r, account.ID, id)
	imageSources := "data: cid:"
	if allowRemote {
		imageSources += " https: http:"
	}
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src "+imageSources+"; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; navigate-to 'none'")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_, _ = w.Write([]byte("<!doctype html><meta charset=utf-8>" + sanitizeHTMLWithRemoteImages(msg.HTMLBody, allowRemote)))
}

func (h *MessageHandler) remoteImagePermit(r *http.Request, accountID, messageID int64) string {
	mac := hmac.New(sha256.New, []byte(h.cfg.Security.CSRFKey))
	_, _ = fmt.Fprintf(mac, "remote-images:%d:%d:%s", accountID, messageID, h.sessionMgr.GenerateCSRFToken(r))
	return hex.EncodeToString(mac.Sum(nil))
}

func (h *MessageHandler) remoteImagesAllowed(r *http.Request, accountID, messageID int64) bool {
	if r.URL.Query().Get("remote_images") != "1" {
		return false
	}
	token := r.URL.Query().Get("permit")
	if len(token) != 64 {
		return false
	}
	expected := h.remoteImagePermit(r, accountID, messageID)
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

// BulkAction applies an account-scoped, atomic action to selected messages.
func (h *MessageHandler) BulkAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if !h.sessionMgr.ValidateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var request struct {
		IDs      []int64 `json:"ids"`
		Action   string  `json:"action"`
		FolderID int64   `json:"folder_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	var err error
	if request.Action == "delete" {
		err = h.db.PermanentlyDeleteMessages(account.ID, request.IDs)
	} else {
		err = h.db.ApplyMessageAction(account.ID, request.IDs, request.Action, request.FolderID)
	}
	if err != nil {
		http.Error(w, "Unable to update selection: check messages and destination", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}
