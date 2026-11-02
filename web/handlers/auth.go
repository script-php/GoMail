package handlers

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"gomail/metrics"
	"gomail/security"
	"gomail/store"
	"gomail/templates"
)

// LoginRateLimiter interface for rate limiting login attempts (IP-based).
type LoginRateLimiter interface {
	IsBlocked(ip string) (bool, time.Duration)
	RecordFailure(ip string)
	RecordSuccess(ip string)
}

// AuthHandler handles login/logout.
type AuthHandler struct {
	db               *store.DB
	sessionMgr       *security.SessionManager
	loginRateLimiter LoginRateLimiter
	templates        *template.Template
}

// NewAuthHandler creates an auth handler.
func NewAuthHandler(db *store.DB, sm *security.SessionManager) *AuthHandler {
	// Use embedded templates
	funcMap := template.FuncMap{}
	tmpl := templates.LoadTemplate(funcMap, "base", "login", "welcome")
	return &AuthHandler{
		db:         db,
		sessionMgr: sm,
		templates:  tmpl,
	}
}

// SetLoginRateLimiter sets the login rate limiter.
func (h *AuthHandler) SetLoginRateLimiter(limiter LoginRateLimiter) {
	h.loginRateLimiter = limiter
}

// LoginPage shows the login form or processes a login attempt.
func (h *AuthHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// If already logged in, redirect to home
	if h.sessionMgr.GetSession(r) != "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	data := map[string]interface{}{
		"Error": "",
	}

	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if !h.sessionMgr.ValidateLoginCSRF(r) {
			loginToken, err := h.sessionMgr.IssueLoginCSRFToken(w, r)
			if err != nil {
				http.Error(w, "Unable to prepare login form", http.StatusInternalServerError)
				return
			}
			data["Error"] = "This sign-in form expired or was replaced. Please try again."
			data["Email"] = r.FormValue("email")
			data["LoginCSRFToken"] = loginToken
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
				log.Printf("[web] login template error: %v", err)
			}
			return
		}
		email := r.FormValue("email")
		password := r.FormValue("password")
		clientIP := getClientIP(r)
		log.Printf("[auth] login attempt for %s from IP %s", email, clientIP)

		// Check if IP is blocked from brute-force attempts
		if h.loginRateLimiter != nil {
			blocked, remaining := h.loginRateLimiter.IsBlocked(clientIP)
			if blocked {
				metrics.IncLogin("blocked")
				data["Error"] = fmt.Sprintf("Too many failed login attempts. Try again in %d seconds", int(remaining.Seconds())+1)
				log.Printf("[auth] IP %s is blocked, showing lockout message", clientIP)
				loginToken, err := h.sessionMgr.IssueLoginCSRFToken(w, r)
				if err != nil {
					http.Error(w, "Unable to prepare login form", http.StatusInternalServerError)
					return
				}
				data["LoginCSRFToken"] = loginToken
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
					log.Printf("[web] template error: %v", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
				return
			}
		}

		authenticated, authErr := h.authenticate(email, password)
		if authErr != nil {
			http.Error(w, "Authentication temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if authenticated {
			log.Printf("[auth] auth succeeded for %s from IP %s, clearing failures", email, clientIP)
			if h.loginRateLimiter != nil {
				h.loginRateLimiter.RecordSuccess(clientIP)
			}
			if err := h.sessionMgr.CreateSession(w, email); err != nil {
				log.Printf("[web] session creation error: %v", err)
				data["Error"] = "Internal error, please try again"
			} else {
				h.sessionMgr.ClearLoginCSRF(w)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
		} else {
			metrics.IncLogin("failed")
			log.Printf("[auth] auth failed for %s from IP %s, recording failure", email, clientIP)
			if h.loginRateLimiter != nil {
				h.loginRateLimiter.RecordFailure(clientIP)
			}
			data["Error"] = "Invalid email or password"
		}
	}
	loginToken, err := h.sessionMgr.IssueLoginCSRFToken(w, r)
	if err != nil {
		http.Error(w, "Unable to prepare login form", http.StatusInternalServerError)
		return
	}
	data["LoginCSRFToken"] = loginToken

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[web] template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Logout destroys the session and redirects to login.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.sessionMgr.ValidateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	h.sessionMgr.DestroySession(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *AuthHandler) authenticate(email, password string) (bool, error) {
	if email == "" || password == "" {
		log.Printf("[auth] authenticate failed: empty email or password")
		return false, nil
	}

	account, err := h.db.GetAccountByEmail(email)
	if err != nil {
		log.Printf("[auth] GetAccountByEmail(%s) error: %v", email, err)
		return false, err
	}
	if account == nil {
		log.Printf("[auth] GetAccountByEmail(%s) returned nil account", email)
		return false, nil
	}

	if !account.IsActive {
		log.Printf("[auth] account %s is not active", email)
		return false, nil
	}

	err = bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(password))
	if err != nil {
		log.Printf("[auth] bcrypt.CompareHashAndPassword failed for %s: %v", email, err)
		return false, nil
	}
	log.Printf("[auth] authentication successful for %s", email)
	return true, nil
}

// getClientIP extracts the client IP from the request (handles X-Forwarded-For).
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For first (if behind reverse proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}
