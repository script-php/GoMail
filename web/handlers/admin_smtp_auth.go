package handlers

import (
	"net/http"

	"gomail/store"
	"gomail/templates"
)

func (h *AdminHandler) SMTPAuth(w http.ResponseWriter, r *http.Request) {
	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil || !account.IsAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	errorMessage, successMessage := "", ""
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
		if err := h.db.SetSMTPAdminAuthMode(store.SMTPAuthMode(r.FormValue("mode"))); err != nil {
			errorMessage = err.Error()
		} else {
			successMessage = "SMTP login policy saved. Changes apply to new authentication attempts."
		}
	}
	mode, err := h.db.SMTPAdminAuthMode()
	if err != nil {
		http.Error(w, "Unable to load SMTP policy", http.StatusInternalServerError)
		return
	}
	data := map[string]interface{}{"Title": "SMTP authentication", "Section": "admin", "AdminPanel": "smtp-auth", "Account": account, "CSRFToken": h.sessionMgr.GenerateCSRFToken(r), "Mode": mode, "Error": errorMessage, "Success": successMessage}
	tmpl := templates.LoadTemplate(nil, "base", "admin_smtp_auth", "welcome")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.ExecuteTemplate(w, "base.html", data)
}
