package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"

	"gomail/security"
	"gomail/store"
	"gomail/templates"
)

// InboxHandler handles inbox and sent message listing.
type InboxHandler struct {
	db         *store.DB
	sessionMgr *security.SessionManager
	templates  *template.Template
	cursors    *cursorSigner
}

// NewInboxHandler creates an inbox handler.
func NewInboxHandler(db *store.DB, sm *security.SessionManager, secrets ...string) *InboxHandler {
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
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"folderID": func(id *int64) int64 {
			if id == nil {
				return 0
			}
			return *id
		},
	}

	tmpl := templates.LoadTemplate(funcMap, "base", "inbox", "welcome")

	secret := ""
	if len(secrets) > 0 {
		secret = secrets[0]
	}
	return &InboxHandler{
		db:         db,
		sessionMgr: sm,
		templates:  tmpl,
		cursors:    newCursorSigner(secret),
	}
}

func (h *InboxHandler) cursor(r *http.Request, accountID int64, scope string) (*store.MessageCursor, error) {
	value := r.URL.Query().Get("cursor")
	if value == "" {
		return nil, nil
	}
	return h.cursors.decode(value, accountID, scope)
}

func (h *InboxHandler) pageData(accountID int64, scope string, page store.MessagePage) map[string]interface{} {
	data := map[string]interface{}{"Messages": page.Messages, "HasOlder": page.HasOlder, "HasNewer": page.HasNewer}
	if len(page.Messages) > 0 {
		if page.HasNewer {
			data["NewerCursor"] = h.cursors.encode(accountID, scope, "newer", page.Messages[0])
		}
		if page.HasOlder {
			data["OlderCursor"] = h.cursors.encode(accountID, scope, "older", page.Messages[len(page.Messages)-1])
		}
	}
	return data
}

// Inbox shows the inbox (inbound messages).
func (h *InboxHandler) Inbox(w http.ResponseWriter, r *http.Request) {
	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	perPage := 50
	scope := directionScope("inbound")
	cursor, err := h.cursor(r, account.ID, scope)
	if err != nil {
		http.Error(w, "Invalid mailbox cursor", http.StatusBadRequest)
		return
	}
	page, err := h.db.ListMessagesPage(account.ID, "inbound", perPage, cursor)
	if err != nil {
		log.Printf("[web] inbox list error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	total, _ := h.db.CountMessages(account.ID, "inbound")
	unread, _ := h.db.CountUnread(account.ID)
	folders, _ := h.db.ListFolders(account.ID)

	data := h.pageData(account.ID, scope, page)
	for key, value := range map[string]interface{}{
		"Title":     "Inbox",
		"Total":     total,
		"Unread":    unread,
		"CSRFToken": h.sessionMgr.GenerateCSRFToken(r),
		"Section":   "inbox",
		"Account":   account,
		"Folders":   folders,
	} {
		data[key] = value
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[web] template error: %v", err)
	}
}

// Starred shows bookmarked messages from all non-trash folders.
func (h *InboxHandler) Starred(w http.ResponseWriter, r *http.Request) {
	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	const scope = "starred"
	cursor, err := h.cursor(r, account.ID, scope)
	if err != nil {
		http.Error(w, "Invalid mailbox cursor", http.StatusBadRequest)
		return
	}
	page, err := h.db.ListStarredMessagesPage(account.ID, 50, cursor)
	if err != nil {
		log.Printf("[web] starred list error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	total, err := h.db.CountStarredMessages(account.ID)
	if err != nil {
		log.Printf("[web] starred count error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	unread, _ := h.db.CountUnread(account.ID)
	folders, _ := h.db.ListFolders(account.ID)
	data := h.pageData(account.ID, scope, page)
	for key, value := range map[string]interface{}{
		"Title": "Starred", "Total": total, "Unread": unread,
		"CSRFToken": h.sessionMgr.GenerateCSRFToken(r), "Section": "starred",
		"Account": account, "Folders": folders,
	} {
		data[key] = value
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[web] template error: %v", err)
	}
}

// Sent shows the sent (outbound) messages.
func (h *InboxHandler) Sent(w http.ResponseWriter, r *http.Request) {
	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	perPage := 50
	scope := directionScope("outbound")
	cursor, err := h.cursor(r, account.ID, scope)
	if err != nil {
		http.Error(w, "Invalid mailbox cursor", http.StatusBadRequest)
		return
	}
	page, err := h.db.ListMessagesPage(account.ID, "outbound", perPage, cursor)
	if err != nil {
		log.Printf("[web] sent list error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	total, _ := h.db.CountMessages(account.ID, "outbound")
	unread, _ := h.db.CountUnread(account.ID)
	folders, _ := h.db.ListFolders(account.ID)

	data := h.pageData(account.ID, scope, page)
	for key, value := range map[string]interface{}{
		"Title":     "Sent",
		"Total":     total,
		"Unread":    unread,
		"CSRFToken": h.sessionMgr.GenerateCSRFToken(r),
		"Section":   "sent",
		"Account":   account,
		"Folders":   folders,
	} {
		data[key] = value
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[web] template error: %v", err)
	}
}

// UnreadCount returns the unread count as JSON (for AJAX polling).
func (h *InboxHandler) UnreadCount(w http.ResponseWriter, r *http.Request) {
	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	count, err := h.db.CountUnread(account.ID)
	if err != nil {
		http.Error(w, "Unable to count messages", http.StatusInternalServerError)
		return
	}
	folders, err := h.db.ListFolders(account.ID)
	if err != nil {
		http.Error(w, "Unable to count folders", http.StatusInternalServerError)
		return
	}
	counts := make(map[int64]int)
	for _, folder := range folders {
		counts[folder.ID] = folder.UnreadCount
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"unread": count, "folders": counts})
}

// FolderView shows messages in a specific folder by folder ID.
func (h *InboxHandler) FolderView(w http.ResponseWriter, r *http.Request) {
	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Extract folder ID from URL path: /folder/{folderID}
	folderIDStr := r.PathValue("folderID")
	folderID, err := strconv.ParseInt(folderIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid folder ID", http.StatusBadRequest)
		return
	}

	// Get folder and verify it belongs to this account
	folder, err := h.db.GetFolderByID(folderID)
	if err != nil || folder == nil || folder.AccountID != account.ID {
		http.Error(w, "Folder not found", http.StatusNotFound)
		return
	}

	perPage := 50
	scope := folderScope(folderID)
	cursor, err := h.cursor(r, account.ID, scope)
	if err != nil {
		http.Error(w, "Invalid mailbox cursor", http.StatusBadRequest)
		return
	}
	page, err := h.db.ListFolderMessagesPage(account.ID, folderID, perPage, cursor)
	if err != nil {
		log.Printf("[web] folder view error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	total := folder.TotalCount
	unread, _ := h.db.CountUnread(account.ID)
	folders, _ := h.db.ListFolders(account.ID)

	data := h.pageData(account.ID, scope, page)
	for key, value := range map[string]interface{}{
		"Title":        folder.Name,
		"Total":        total,
		"Unread":       unread,
		"CSRFToken":    h.sessionMgr.GenerateCSRFToken(r),
		"Section":      "folder",
		"Account":      account,
		"Folders":      folders,
		"ActiveFolder": folderID,
		"IsTrash":      folder.FolderType == "trash",
		"FolderType":   folder.FolderType,
	} {
		data[key] = value
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[web] template error: %v", err)
	}
}

// Welcome shows the welcome/home page.
func (h *InboxHandler) Welcome(w http.ResponseWriter, r *http.Request) {
	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	unread, _ := h.db.CountUnread(account.ID)
	folders, _ := h.db.ListFolders(account.ID)

	data := map[string]interface{}{
		"Title":     "Welcome",
		"Unread":    unread,
		"CSRFToken": h.sessionMgr.GenerateCSRFToken(r),
		"Section":   "welcome",
		"Account":   account,
		"Folders":   folders,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[web] template error: %v", err)
	}
}

// Search shows matching messages from this account, excluding Trash.
func (h *InboxHandler) Search(w http.ResponseWriter, r *http.Request) {
	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(query) > 500 {
		http.Error(w, "Search is too long", http.StatusBadRequest)
		return
	}
	scope := searchScope(query)
	cursor, err := h.cursor(r, account.ID, scope)
	if err != nil {
		http.Error(w, "Invalid search cursor", http.StatusBadRequest)
		return
	}
	page, total, err := h.db.SearchMessagesPage(account.ID, query, 50, cursor)
	if err != nil {
		http.Error(w, "Unable to search mail", http.StatusInternalServerError)
		return
	}
	folders, _ := h.db.ListFolders(account.ID)
	unread, _ := h.db.CountUnread(account.ID)
	data := h.pageData(account.ID, scope, page)
	for key, value := range map[string]interface{}{
		"Title": "Search", "Section": "search", "Query": query,
		"Total":   total,
		"Account": account, "Folders": folders, "Unread": unread,
		"CSRFToken": h.sessionMgr.GenerateCSRFToken(r),
	} {
		data[key] = value
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[web] search template: %v", err)
	}
}
