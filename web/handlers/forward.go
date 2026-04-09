package handlers

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"gomail/auth"
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
	funcMap := template.FuncMap{}
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

	// Prepare forward form with original message details
	data := map[string]interface{}{
		"Section":         "forward",
		"OriginalMsg":     originalMsg,
		"OriginalFrom":    originalMsg.FromAddr,
		"OriginalTo":      originalMsg.ToAddr,
		"OriginalCC":      originalMsg.CcAddr,
		"OriginalSubject": "Fwd: " + originalMsg.Subject,
		"OriginalText":    originalMsg.TextBody,
		"Account":         account,
		"CSRFToken":       h.sessionMgr.GenerateCSRFToken(r),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
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
	subject := r.FormValue("subject")
	forwardNotes := r.FormValue("forward_notes")

	if msgIDStr == "" || to == "" {
		http.Error(w, "Message ID and recipient are required", http.StatusBadRequest)
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

	// Build Received header - show IP only if explicitly enabled
	var receivedLine string
	if h.cfg.Mail.StripOriginatingIP {
		receivedLine = fmt.Sprintf("Received: from webmail (%s)\r\n\tby %s with HTTP (GoMail)\r\n\tid %s\r\n\tfor <%s>;\r\n\t%s",
			clientIP,
			h.cfg.Server.Hostname,
			msgID2,
			to,
			time.Now().Format(time.RFC1123Z),
		)
	} else {
		receivedLine = fmt.Sprintf("Received: from webmail\r\n\tby %s with HTTP (GoMail)\r\n\tid %s\r\n\tfor <%s>;\r\n\t%s",
			h.cfg.Server.Hostname,
			msgID2,
			to,
			time.Now().Format(time.RFC1123Z),
		)
	}
	msg.WriteString(receivedLine + "\r\n")

	// Add Resent- headers (RFC 5322 forwarding convention)
	msg.WriteString(fmt.Sprintf("Resent-From: %s\r\n", from))
	msg.WriteString(fmt.Sprintf("Resent-Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	msg.WriteString(fmt.Sprintf("Resent-To: %s\r\n", to))
	if cc != "" {
		msg.WriteString(fmt.Sprintf("Resent-Cc: %s\r\n", cc))
	}
	msg.WriteString(fmt.Sprintf("Resent-Message-ID: %s\r\n", msgID2))

	// Original headers (preserved from forwarded message)
	msg.WriteString(fmt.Sprintf("From: %s\r\n", originalMsg.FromAddr))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", originalMsg.ToAddr))
	if originalMsg.CcAddr != "" {
		msg.WriteString(fmt.Sprintf("Cc: %s\r\n", originalMsg.CcAddr))
	}
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString(fmt.Sprintf("Date: %s\r\n", originalMsg.ReceivedAt.Format(time.RFC1123Z)))
	msg.WriteString(fmt.Sprintf("Message-ID: %s\r\n", originalMsg.MessageID))

	// User agent
	msg.WriteString(fmt.Sprintf("User-Agent: %s\r\n", config.UserAgent()))

	// Include X-Originating-IP unless disabled in config
	if !h.cfg.Mail.StripOriginatingIP {
		msg.WriteString(fmt.Sprintf("X-Originating-IP: [%s]\r\n", clientIP))
	}

	// ADD ARC HEADERS WITH CHAIN SUPPORT
	// Extract existing ARC chain from original message
	// We need to include original ARC headers so delivery worker detects this as a forward (i=2+)
	var arcHeadersFromOriginal []string
	var messageToEnqueue []byte

	// For inbound messages, RawMessage might be empty, so try RawHeaders first
	var messageForExtraction []byte
	if len(originalMsg.RawMessage) > 0 {
		messageForExtraction = originalMsg.RawMessage
		log.Printf("[forward.Send] using RawMessage for ARC extraction (size=%d)", len(originalMsg.RawMessage))
	} else if len(originalMsg.RawHeaders) > 0 {
		// Reconstruct minimal message from RawHeaders + body for ARC extraction
		messageForExtraction = append([]byte(originalMsg.RawHeaders+"\r\n\r\n"), []byte(originalMsg.TextBody)...)
		log.Printf("[forward.Send] reconstructed message from RawHeaders for ARC extraction (headers_size=%d)", len(originalMsg.RawHeaders))
	}

	log.Printf("[forward.Send] ARC extraction START: has_message=%v, msg_len=%d",
		len(messageForExtraction) > 0, len(messageForExtraction))

	if len(messageForExtraction) > 0 {
		existingInstance := auth.GetHighestArcInstance(messageForExtraction)
		log.Printf("[forward.Send] checking original message for ARC chain: instance=%d, msg_size=%d",
			existingInstance, len(messageForExtraction))

		if existingInstance > 0 {
			log.Printf("[forward.Send] preserving existing ARC chain at instance=%d", existingInstance)
			existingARC := auth.ExtractArcHeaders(messageForExtraction)
			log.Printf("[forward.Send] extracted ARC headers: %d instances found", len(existingARC))

			// Extract all ARC headers from the original message
			// These will be prepended to the new forward message
			for i := 1; i <= existingInstance; i++ {
				if headerMap, ok := existingARC[i]; ok {
					log.Printf("[forward.Send] instance %d: auth-results=%v, msg-sig=%v, seal=%v",
						i,
						len(headerMap["auth-results"]) > 0,
						len(headerMap["message-signature"]) > 0,
						len(headerMap["seal"]) > 0)

					// Add in correct order: auth-results, message-signature, seal
					if authResult := headerMap["auth-results"]; authResult != "" {
						arcHeadersFromOriginal = append(arcHeadersFromOriginal, authResult)
					}
					if msgSig := headerMap["message-signature"]; msgSig != "" {
						arcHeadersFromOriginal = append(arcHeadersFromOriginal, msgSig)
					}
					if seal := headerMap["seal"]; seal != "" {
						arcHeadersFromOriginal = append(arcHeadersFromOriginal, seal)
					}
				}
			}
			log.Printf("[forward.Send] collected %d ARC header strings from original", len(arcHeadersFromOriginal))
		}
	}

	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	msg.WriteString("\r\n")

	// Add forwarding note if provided
	if forwardNotes != "" {
		msg.WriteString("--- Forwarded message ---\r\n")
		msg.WriteString(forwardNotes)
		msg.WriteString("\r\n\r\n")
	}

	// Add original message body
	msg.WriteString("--- Original Message ---\r\n")
	msg.WriteString("From: " + originalMsg.FromAddr + "\r\n")
	msg.WriteString("To: " + originalMsg.ToAddr + "\r\n")
	if originalMsg.CcAddr != "" {
		msg.WriteString("Cc: " + originalMsg.CcAddr + "\r\n")
	}
	msg.WriteString("Date: " + originalMsg.ReceivedAt.Format(time.RFC1123Z) + "\r\n")
	msg.WriteString("Subject: " + originalMsg.Subject + "\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(originalMsg.TextBody)

	// Rebuild messageToEnqueue with complete message content
	if len(arcHeadersFromOriginal) > 0 {
		// Prepend original ARC headers to the complete message
		// This allows NextArcInstance() to detect the chain
		arcHeaderStr := strings.Join(arcHeadersFromOriginal, "\r\n") + "\r\n"
		messageToEnqueue = append([]byte(arcHeaderStr), []byte(msg.String())...)
		log.Printf("[forward.Send] prepended %d ARC headers, final message size=%d",
			len(arcHeadersFromOriginal), len(messageToEnqueue))
	} else {
		messageToEnqueue = []byte(msg.String())
		log.Printf("[forward.Send] no ARC headers to prepend, message size=%d", len(messageToEnqueue))
	}

	// Enqueue for delivery
	if err := h.queue.Enqueue(from, recipients, messageToEnqueue, account.ID); err != nil {
		log.Printf("[forward] enqueue error: %v", err)
		http.Error(w, "Failed to forward message", http.StatusInternalServerError)
		return
	}

	log.Printf("[forward] message forwarded from=%s to=%v msgID=%d", from, recipients, msgID)
	http.Redirect(w, r, "/message/"+msgIDStr, http.StatusSeeOther)
}
