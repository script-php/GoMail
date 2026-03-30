package handlers

import (
	"html/template"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"gomail/security"
	"gomail/store"
	"gomail/templates"
)

// AuthHandler handles login/logout.
type AuthHandler struct {
	db         *store.DB
	sessionMgr *security.SessionManager
	templates  *template.Template
}

// NewAuthHandler creates an auth handler.
func NewAuthHandler(db *store.DB, sm *security.SessionManager) *AuthHandler {
	// Use embedded templates
	tmpl := templates.LoadSimpleTemplate("base", "login")
	return &AuthHandler{
		db:         db,
		sessionMgr: sm,
		templates:  tmpl,
	}
}

// LoginPage shows the login form or processes a login attempt.
func (h *AuthHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	// If already logged in, redirect to inbox
	if h.sessionMgr.GetSession(r) != "" {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}

	data := map[string]interface{}{
		"Error": "",
	}

	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")

		if h.authenticate(email, password) {
			if err := h.sessionMgr.CreateSession(w, email); err != nil {
				log.Printf("[web] session creation error: %v", err)
				data["Error"] = "Internal error, please try again"
			} else {
				http.Redirect(w, r, "/inbox", http.StatusSeeOther)
				return
			}
		} else {
			data["Error"] = "Invalid email or password"
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[web] template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Logout destroys the session and redirects to login.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	h.sessionMgr.DestroySession(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *AuthHandler) authenticate(email, password string) bool {
	if email == "" || password == "" {
		return false
	}

	account, err := h.db.GetAccountByEmail(email)
	if err != nil || account == nil {
		return false
	}

	if !account.IsActive {
		return false
	}

	err = bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(password))
	return err == nil
}
