package handlers

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
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
	funcMap := template.FuncMap{"formatSize": func(size int64) string {
		switch {
		case size >= 1073741824:
			return fmt.Sprintf("%.1f GB", float64(size)/1073741824)
		case size >= 1048576:
			return fmt.Sprintf("%.1f MB", float64(size)/1048576)
		case size >= 1024:
			return fmt.Sprintf("%.1f KB", float64(size)/1024)
		default:
			return fmt.Sprintf("%d B", size)
		}
	}}
	return &SettingsHandler{db: db, sessionMgr: sm, templates: templates.LoadTemplate(funcMap, "base", "settings", "welcome")}
}

func (h *SettingsHandler) Settings(w http.ResponseWriter, r *http.Request) {
	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	errorMessage, successMessage := "", ""
	newSMTPSecret := ""
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}
		if !h.sessionMgr.ValidateCSRF(r) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		if action := r.FormValue("action"); action == "smtp-policy" || action == "smtp-app-create" || action == "smtp-app-revoke" {
			if bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(r.FormValue("current_password"))) != nil {
				errorMessage = "Current password is incorrect."
			} else {
				switch action {
				case "smtp-policy":
					if err := h.db.SetSMTPUserAuthMode(account.ID, store.SMTPAuthMode(r.FormValue("mode"))); err != nil {
						errorMessage = err.Error()
					} else {
						successMessage = "SMTP login preference saved."
					}
				case "smtp-app-create":
					var err error
					newSMTPSecret, err = h.db.CreateSMTPAppPassword(account.ID, r.FormValue("name"))
					if err != nil {
						errorMessage = err.Error()
					} else {
						successMessage = "App credential created. Copy it now; it cannot be shown again."
					}
				case "smtp-app-revoke":
					id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
					if err == nil && id > 0 {
						err = h.db.RevokeSMTPAppPassword(account.ID, id)
					}
					if err != nil || id <= 0 {
						errorMessage = "Unable to revoke app credential."
					} else {
						successMessage = "App credential revoked."
					}
				}
			}
		} else if action := r.FormValue("action"); action == "alias-create" || action == "alias-delete" {
			if !account.AllowAliases {
				http.Error(w, "Alias permission is disabled", http.StatusForbidden)
				return
			}
			var err error
			if action == "alias-create" {
				err = h.db.CreateUserAlias(r.FormValue("address"), account.ID)
			} else {
				err = h.db.DeleteUserAlias(r.FormValue("address"), account.ID)
			}
			if err != nil {
				errorMessage = err.Error()
			} else {
				successMessage = "Alias settings saved."
			}
		} else if action := r.FormValue("action"); action != "" && action != "profile" {
			http.Error(w, "Invalid action", http.StatusBadRequest)
			return
		} else {
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
					if len(newHash) > 0 {
						h.sessionMgr.DestroySession(w, r)
						http.Redirect(w, r, "/login", http.StatusSeeOther)
						return
					}
					successMessage = "Settings saved."
					account, _ = h.db.GetAccount(account.ID)
				}
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
		"Error": errorMessage, "Success": successMessage, "NewSMTPSecret": newSMTPSecret}
	adminMode, err := h.db.SMTPAdminAuthMode()
	if err != nil {
		http.Error(w, "Unable to load SMTP policy", http.StatusInternalServerError)
		return
	}
	userMode, err := h.db.SMTPUserAuthMode(account.ID)
	if err != nil {
		http.Error(w, "Unable to load SMTP preference", http.StatusInternalServerError)
		return
	}
	credentials, err := h.db.ListSMTPAppPasswords(account.ID)
	if err != nil {
		http.Error(w, "Unable to load app credentials", http.StatusInternalServerError)
		return
	}
	data["SMTPAdminMode"], data["SMTPUserMode"], data["SMTPAppCredentials"] = adminMode, userMode, credentials
	data["SMTPPasswordAllowed"] = adminMode == store.SMTPAuthBoth || adminMode == store.SMTPAuthPassword
	data["SMTPAppAllowed"] = adminMode == store.SMTPAuthBoth || adminMode == store.SMTPAuthApp
	passwordEffective, appEffective, err := h.db.SMTPAllowedCredentials(account.ID)
	if err != nil {
		http.Error(w, "Unable to load SMTP preference", http.StatusInternalServerError)
		return
	}
	selectedMode := store.SMTPAuthDisabled
	if passwordEffective && appEffective {
		selectedMode = store.SMTPAuthBoth
	} else if passwordEffective {
		selectedMode = store.SMTPAuthPassword
	} else if appEffective {
		selectedMode = store.SMTPAuthApp
	}
	data["SMTPSelectedMode"] = selectedMode
	w.Header().Set("Cache-Control", "no-store")
	if account.AllowAliases {
		aliases, err := h.db.ListUserAliases(account.ID)
		if err != nil {
			http.Error(w, "Unable to load aliases", http.StatusInternalServerError)
			return
		}
		data["Aliases"] = aliases
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[web] settings template error: %v", err)
	}
}
