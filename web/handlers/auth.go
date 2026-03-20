package handlers

import (
	"html/template"
	"log"
	"net/http"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"

	"gomail/config"
	"gomail/security"
	"gomail/store"
)

// AuthHandler handles login/logout.
type AuthHandler struct {
	cfg        *config.Config
	db         *store.DB
	sessionMgr *security.SessionManager
	templates  *template.Template
}

// NewAuthHandler creates an auth handler.
func NewAuthHandler(cfg *config.Config, db *store.DB, sm *security.SessionManager) *AuthHandler {
	tmpl := template.Must(template.ParseFiles(
		filepath.Join("web", "templates", "base.html"),
		filepath.Join("web", "templates", "login.html"),
	))
	return &AuthHandler{
		cfg:        cfg,
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
		username := r.FormValue("username")
		password := r.FormValue("password")

		if h.authenticate(username, password) {
			if err := h.sessionMgr.CreateSession(w, username); err != nil {
				log.Printf("[web] session creation error: %v", err)
				data["Error"] = "Internal error, please try again"
			} else {
				http.Redirect(w, r, "/inbox", http.StatusSeeOther)
				return
			}
		} else {
			data["Error"] = "Invalid username or password"
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

func (h *AuthHandler) authenticate(username, password string) bool {
	if username != h.cfg.Web.Admin.Username {
		return false
	}

	// If password hash is set, use bcrypt
	if h.cfg.Web.Admin.PasswordHash != "" {
		err := bcrypt.CompareHashAndPassword(
			[]byte(h.cfg.Web.Admin.PasswordHash),
			[]byte(password),
		)
		return err == nil
	}

	// Fallback: no hash set means first-run; reject all logins
	// User must run setup script first
	log.Println("[web] warning: no password hash set; run setup.sh to configure admin password")
	return false
}
