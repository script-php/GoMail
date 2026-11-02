package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gomail/store"
)

const (
	sessionCookieName   = "gomail_session"
	loginCSRFCookieName = "gomail_login_csrf"
	csrfCookieName      = "gomail_csrf"
	csrfFormField       = "csrf_token"
	csrfHeaderName      = "X-CSRF-Token"
)

// IssueLoginCSRFToken binds the unauthenticated login form to this browser.
func (sm *SessionManager) IssueLoginCSRFToken(w http.ResponseWriter, r *http.Request) (string, error) {
	token := ""
	if existing, err := r.Cookie(loginCSRFCookieName); err == nil && sm.validLoginCSRFCookie(existing.Value) {
		token = existing.Value
	} else {
		random, err := generateToken(32)
		if err != nil {
			return "", err
		}
		token = random + "." + sm.loginCookieSignature(random)
	}
	http.SetCookie(w, &http.Cookie{Name: loginCSRFCookieName, Value: token, Path: "/login", HttpOnly: true, Secure: sm.secureCookie, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	return generateCSRF(token, sm.csrfKey), nil
}

func (sm *SessionManager) loginCookieSignature(random string) string {
	mac := hmac.New(sha256.New, []byte(sm.csrfKey))
	_, _ = mac.Write([]byte("gomail-login-csrf:" + random))
	return hex.EncodeToString(mac.Sum(nil))
}

func (sm *SessionManager) validLoginCSRFCookie(value string) bool {
	random, signature, ok := strings.Cut(value, ".")
	if !ok || len(random) != 64 || len(signature) != 64 {
		return false
	}
	if _, err := hex.DecodeString(random); err != nil {
		return false
	}
	if _, err := hex.DecodeString(signature); err != nil {
		return false
	}
	expected := sm.loginCookieSignature(random)
	return subtle.ConstantTimeCompare([]byte(signature), []byte(expected)) == 1
}

// ValidateLoginCSRF checks the pre-login cookie and form token together.
func (sm *SessionManager) ValidateLoginCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(loginCSRFCookieName)
	if err != nil || !sm.validLoginCSRFCookie(cookie.Value) {
		return false
	}
	expected := generateCSRF(cookie.Value, sm.csrfKey)
	return subtle.ConstantTimeCompare([]byte(r.FormValue(csrfFormField)), []byte(expected)) == 1
}

func (sm *SessionManager) ClearLoginCSRF(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: loginCSRFCookieName, Path: "/login", HttpOnly: true, Secure: sm.secureCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// SessionManager handles web sessions backed by the database.
type SessionManager struct {
	db           *store.DB
	maxAge       int
	csrfKey      string
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
// The email parameter is stored as the session identifier.
func (sm *SessionManager) CreateSession(w http.ResponseWriter, email string) error {
	token, err := generateToken(32)
	if err != nil {
		return fmt.Errorf("generating session token: %w", err)
	}

	expiresAt := time.Now().Add(time.Duration(sm.maxAge) * time.Second)

	if err := sm.db.SaveSession(token, email, expiresAt); err != nil {
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

// GetSession returns the email for the current session, or empty if not authenticated.
func (sm *SessionManager) GetSession(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}

	email, err := sm.db.GetSession(cookie.Value)
	if err != nil || email == "" {
		return ""
	}

	account, err := sm.db.GetAccountByEmail(email)
	if err != nil || account == nil || !account.IsActive {
		return ""
	}
	return email
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

	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

// RequireAuth middleware redirects unauthenticated users to login.
func (sm *SessionManager) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if sm.GetSession(r) == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdmin middleware redirects non-admin users to inbox.
// It checks that the session user exists and has is_admin=true.
func (sm *SessionManager) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		email := sm.GetSession(r)
		if email == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		account, err := sm.db.GetAccountByEmail(email)
		if err != nil || account == nil || !account.IsAdmin {
			http.Redirect(w, r, "/inbox", http.StatusSeeOther)
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
