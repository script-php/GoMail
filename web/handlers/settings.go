package handlers

import (
	"html/template"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"gomail/security"
	"gomail/store"
	"gomail/templates"
)

type SettingsHandler struct {
	db         *store.DB
	sessionMgr *security.SessionManager
	templates  *template.Template
}

func NewSettingsHandler(db *store.DB, sm *security.SessionManager) *SettingsHandler {
	return &SettingsHandler{db: db, sessionMgr: sm, templates: templates.LoadTemplate(nil, "base", "settings", "welcome")}
}

func (h *SettingsHandler) Settings(w http.ResponseWriter, r *http.Request) {
	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	errorMessage, successMessage := "", ""
	if r.Method == http.MethodPost {
		if !h.sessionMgr.ValidateCSRF(r) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		displayName := strings.TrimSpace(r.FormValue("display_name"))
		currentPassword := r.FormValue("current_password")
		newPassword := r.FormValue("new_password")
		confirmPassword := r.FormValue("confirm_password")
		var newHash []byte
		switch {
		case len(displayName) > 100:
			errorMessage = "Display name must be 100 characters or fewer."
		case newPassword != "" || currentPassword != "" || confirmPassword != "":
			if bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(currentPassword)) != nil {
				errorMessage = "Current password is incorrect."
			} else if len(newPassword) < 12 || len([]byte(newPassword)) > 72 {
				errorMessage = "New password must contain 12 to 72 bytes."
			} else if newPassword != confirmPassword {
				errorMessage = "New password confirmation does not match."
			} else {
				var err error
				newHash, err = bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
				if err != nil {
					errorMessage = "Unable to secure the new password."
				}
			}
		}
		if errorMessage == "" {
			if err := h.db.UpdateAccountProfile(account.ID, displayName); err != nil {
				errorMessage = "Unable to update settings."
			} else if len(newHash) > 0 {
				if err := h.db.UpdateAccountPassword(account.ID, string(newHash)); err != nil {
					errorMessage = "Unable to update password."
				}
			}
			if errorMessage == "" {
				successMessage = "Settings saved."
				account, _ = h.db.GetAccount(account.ID)
			}
		}
	} else if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	folders, _ := h.db.ListFolders(account.ID)
	unread, _ := h.db.CountUnread(account.ID)
	data := map[string]interface{}{"Title": "Settings", "Section": "settings", "Account": account,
		"Folders": folders, "Unread": unread, "CSRFToken": h.sessionMgr.GenerateCSRFToken(r),
		"Error": errorMessage, "Success": successMessage}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[web] settings template error: %v", err)
	}
}
