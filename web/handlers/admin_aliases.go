package handlers

import (
	"net/http"
	"strconv"
	"strings"
)

// Aliases manages local virtual recipient addresses without creating logins.
func (h *AdminHandler) Aliases(w http.ResponseWriter, r *http.Request) {
	admin := h.getAdmin(r)
	if admin == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	errorMessage := ""
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
		switch r.FormValue("action") {
		case "create":
			id, err := strconv.ParseInt(r.FormValue("target_account_id"), 10, 64)
			if err != nil || id <= 0 {
				errorMessage = "Select a destination account."
			} else if err := h.db.CreateAlias(r.FormValue("address"), id); err != nil {
				errorMessage = err.Error()
			}
		case "delete":
			address := strings.TrimSpace(r.FormValue("address"))
			if address == "" {
				errorMessage = "Select an alias to delete."
			} else if err := h.db.DeleteAlias(address); err != nil {
				errorMessage = err.Error()
			}
		default:
			http.Error(w, "Invalid action", http.StatusBadRequest)
			return
		}
		if errorMessage == "" {
			http.Redirect(w, r, "/admin/aliases?saved=1", http.StatusSeeOther)
			return
		}
	}
	aliases, err := h.db.ListAliases()
	if err != nil {
		http.Error(w, "Unable to load aliases", http.StatusInternalServerError)
		return
	}
	accounts, err := h.db.ListAccounts(0)
	if err != nil {
		http.Error(w, "Unable to load accounts", http.StatusInternalServerError)
		return
	}
	data := map[string]interface{}{
		"Title": "Aliases", "Section": "admin", "AdminPanel": "aliases", "Account": admin,
		"CSRFToken": h.sessionMgr.GenerateCSRFToken(r), "Aliases": aliases, "Accounts": accounts,
		"Error": errorMessage, "Saved": r.URL.Query().Has("saved"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplAliases.ExecuteTemplate(w, "base.html", data); err != nil {
		http.Error(w, "Unable to render aliases", http.StatusInternalServerError)
	}
}
