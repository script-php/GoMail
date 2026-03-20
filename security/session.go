package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"gomail/store"
)

const (
	sessionCookieName = "gomail_session"
	csrfCookieName    = "gomail_csrf"
	csrfFormField     = "csrf_token"
	csrfHeaderName    = "X-CSRF-Token"
)

// SessionManager handles web sessions backed by the database.
type SessionManager struct {
	db        *store.DB
	maxAge    int
	csrfKey   string
	secureCookie bool
}

// NewSessionManager creates a session manager.
// secureCookie controls whether session cookies are marked Secure (requires HTTPS).
func NewSessionManager(db *store.DB, maxAge int, csrfKey string, secureCookie bool) *SessionManager {
	return &SessionManager{
		db:           db,
		maxAge:       maxAge,
		csrfKey:      csrfKey,
		secureCookie: secureCookie,
	}
}

// CreateSession creates a new authenticated session and sets the cookie.
func (sm *SessionManager) CreateSession(w http.ResponseWriter, username string) error {
	token, err := generateToken(32)
	if err != nil {
		return fmt.Errorf("generating session token: %w", err)
	}

	expiresAt := time.Now().Add(time.Duration(sm.maxAge) * time.Second)

	if err := sm.db.SaveSession(token, username, expiresAt); err != nil {
		return fmt.Errorf("saving session: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   sm.secureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   sm.maxAge,
	})

	return nil
}

// GetSession returns the username for the current session, or empty if not authenticated.
func (sm *SessionManager) GetSession(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}

	username, err := sm.db.GetSession(cookie.Value)
	if err != nil || username == "" {
		return ""
	}

	return username
}

// DestroySession removes the session.
func (sm *SessionManager) DestroySession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		sm.db.DeleteSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   sm.secureCookie,
		MaxAge:   -1,
	})
}

// GenerateCSRFToken creates a CSRF token for forms.
func (sm *SessionManager) GenerateCSRFToken(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return generateCSRF(cookie.Value, sm.csrfKey)
}

// ValidateCSRF checks the CSRF token from form data or header.
func (sm *SessionManager) ValidateCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}

	expected := generateCSRF(cookie.Value, sm.csrfKey)

	// Check form field
	token := r.FormValue(csrfFormField)
	if token == "" {
		// Check header
		token = r.Header.Get(csrfHeaderName)
	}

	return token == expected
}

// RequireAuth middleware redirects unauthenticated users to login.
func (sm *SessionManager) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sm.GetSession(r) == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Helpers

func generateToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateCSRF(sessionToken, key string) string {
	h := sha256.New()
	h.Write([]byte(sessionToken))
	h.Write([]byte(key))
	return hex.EncodeToString(h.Sum(nil))
}
