package handlers

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
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

	// Parse multipart form with 25MB limit
	if err := r.ParseMultipartForm(25 * 1024 * 1024); err != nil {
		http.Error(w, fmt.Sprintf("File too large or invalid form: %v", err), http.StatusBadRequest)
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

	// Extract and validate attachments
	attachmentFiles := r.MultipartForm.File["attachments"]
	var attachmentErrors []string
	var attachmentData []map[string]interface{}
	var totalSize int64

	for i, fileHeader := range attachmentFiles {
		if i >= 10 {
			attachmentErrors = append(attachmentErrors, "Maximum 10 attachments allowed")
			break
		}

		if fileHeader.Size > 25*1024*1024 {
			attachmentErrors = append(attachmentErrors, fmt.Sprintf("File %s exceeds 25MB limit", fileHeader.Filename))
			continue
		}

		totalSize += fileHeader.Size
		if totalSize > 25*1024*1024 {
			attachmentErrors = append(attachmentErrors, "Total attachment size exceeds 25MB limit")
			break
		}

		file, err := fileHeader.Open()
		if err != nil {
			attachmentErrors = append(attachmentErrors, fmt.Sprintf("Cannot read file %s", fileHeader.Filename))
			continue
		}

		// Read file content
		fileContent := make([]byte, fileHeader.Size)
		if _, err := file.Read(fileContent); err != nil {
			file.Close()
			attachmentErrors = append(attachmentErrors, fmt.Sprintf("Cannot read file %s", fileHeader.Filename))
			continue
		}
		file.Close()

		attachmentData = append(attachmentData, map[string]interface{}{
			"filename": fileHeader.Filename,
			"content":  fileContent,
			"size":     fileHeader.Size,
		})
	}

	// If there are attachment errors, re-render compose form with errors
	if len(attachmentErrors) > 0 {
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
			"Error":     strings.Join(attachmentErrors, "; "),
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
	msg.WriteString(fmt.Sprintf("From: %s\r\n", encodeHeaderValue(from)))
	msg.WriteString(fmt.Sprintf("Return-Path: <%s>\r\n", from))

	// Include X-Originating-IP only if explicitly enabled
	if h.cfg.Mail.StripOriginatingIP {
		msg.WriteString(fmt.Sprintf("X-Originating-IP: [%s]\r\n", clientIP))
	}

	msg.WriteString(fmt.Sprintf("To: %s\r\n", encodeHeaderValue(to)))
	if cc != "" {
		msg.WriteString(fmt.Sprintf("Cc: %s\r\n", encodeHeaderValue(cc)))
	}
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", encodeHeaderValue(subject)))
	msg.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	msg.WriteString(fmt.Sprintf("Message-ID: %s\r\n", msgID))
	msg.WriteString(fmt.Sprintf("User-Agent: %s\r\n", config.UserAgent()))
	msg.WriteString(fmt.Sprintf("X-Priority: %s\r\n", priority))
	msg.WriteString(fmt.Sprintf("Priority: %s\r\n", priorityToText(priority)))
	msg.WriteString(fmt.Sprintf("Importance: %s\r\n", priorityToImportance(priority)))
	if readReceipt {
		msg.WriteString(fmt.Sprintf("Disposition-Notification-To: %s\r\n", encodeHeaderValue(from)))
	}

	msg.WriteString("MIME-Version: 1.0\r\n")

	// If there are attachments, build multipart/mixed message
	if len(attachmentData) > 0 {
		boundary := fmt.Sprintf("boundary_%d", time.Now().UnixNano())
		msg.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))
		msg.WriteString("\r\n")

		// Add body as first part
		msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		msg.WriteString("Content-Transfer-Encoding: 8bit\r\n")
		msg.WriteString("\r\n")
		msg.WriteString(body)
		msg.WriteString("\r\n")

		// Add attachments
		for _, attach := range attachmentData {
			filename := attach["filename"].(string)
			content := attach["content"].([]byte)

			msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			msg.WriteString(fmt.Sprintf("Content-Type: application/octet-stream; name=\"%s\"\r\n", encodeHeaderValue(filename)))
			msg.WriteString("Content-Transfer-Encoding: base64\r\n")
			msg.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n", encodeHeaderValue(filename)))
			msg.WriteString("\r\n")

			// Encode content as base64 with line wrapping
			encoded := base64Encode(content)
			msg.WriteString(encoded)
			msg.WriteString("\r\n")
		}

		// Final boundary
		msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		// No attachments - simple text/plain message
		msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		msg.WriteString("Content-Transfer-Encoding: 8bit\r\n")
		msg.WriteString("\r\n")
		msg.WriteString(body)
	}

	// Enqueue for delivery (queue handles per-domain DKIM signing and message saving)
	enqueueErr := h.queue.Enqueue(from, recipients, []byte(msg.String()), account.ID)
	if enqueueErr != nil {
		log.Printf("[web] enqueue error: %v", enqueueErr)
		http.Error(w, "Failed to send message", http.StatusInternalServerError)
		return
	}

	log.Printf("[web] message enqueued from=%s to=%v subject=%s attachments=%d", from, recipients, subject, len(attachmentData))
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

// base64Encode encodes data as base64 with line wrapping at 76 characters (RFC 2045)
func base64Encode(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)

	// Wrap at 76 characters per line (RFC 2045 requirement)
	var result strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		result.WriteString(encoded[i:end])
		result.WriteString("\r\n")
	}

	return result.String()
}

// saveAttachment saves an attachment to disk and creates a database record
func saveAttachment(cfg *config.Config, db *store.DB, messageID int64, attachData map[string]interface{}) error {
	filename := attachData["filename"].(string)
	content := attachData["content"].([]byte)

	// Create attachments directory if it doesn't exist
	attachDir := cfg.Store.AttachmentsPath
	if attachDir == "" {
		attachDir = "data/attachments"
	}
	if err := os.MkdirAll(attachDir, 0755); err != nil {
		return fmt.Errorf("creating attachments dir: %w", err)
	}

	// Generate a unique filename to avoid collisions
	storageName := fmt.Sprintf("%d_%d_%s", messageID, time.Now().UnixNano(), filepath.Base(filename))
	storagePath := filepath.Join(attachDir, storageName)

	// Write attachment to disk
	err := os.WriteFile(storagePath, content, 0644)
	if err != nil {
		return fmt.Errorf("writing attachment to disk: %w", err)
	}

	// Detect content type (use application/octet-stream as default)
	contentType := "application/octet-stream"
	if ext := strings.ToLower(filepath.Ext(filename)); ext != "" {
		if ct, ok := mimeTypes[ext]; ok {
			contentType = ct
		}
	}

	// Save attachment metadata to database
	attachment := &store.Attachment{
		MessageID:   messageID,
		Filename:    filename,
		ContentType: contentType,
		Size:        int64(len(content)),
		StoragePath: storagePath,
	}

	_, err = db.SaveAttachment(attachment)
	if err != nil {
		// Clean up the file if database save fails
		os.Remove(storagePath)
		return fmt.Errorf("saving attachment to database: %w", err)
	}

	log.Printf("[web] attachment saved: filename=%s, size=%d, msgID=%d", filename, len(content), messageID)
	return nil
}

// mimeTypes maps common file extensions to MIME types
var mimeTypes = map[string]string{
	".pdf":  "application/pdf",
	".doc":  "application/msword",
	".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	".xls":  "application/vnd.ms-excel",
	".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	".ppt":  "application/vnd.ms-powerpoint",
	".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	".txt":  "text/plain",
	".csv":  "text/csv",
	".zip":  "application/zip",
	".rar":  "application/x-rar-compressed",
	".7z":   "application/x-7z-compressed",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".png":  "image/png",
	".gif":  "image/gif",
	".bmp":  "image/bmp",
	".mp3":  "audio/mpeg",
	".mp4":  "video/mp4",
	".avi":  "video/x-msvideo",
	".mov":  "video/quicktime",
}
