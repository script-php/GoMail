package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"gomail/config"
	"gomail/delivery"
	"gomail/store"
)

func TestLoginAndLogoutRequireCSRF(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	domainID, err := db.CreateDomain(&store.Domain{Domain: "example.test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "alice@example.test", PasswordHash: string(hash), IsActive: true}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Web.SessionMaxAge = 3600
	cfg.Security.CSRFKey = "csrf-test-key"
	server := NewServer(cfg, db, delivery.NewQueue(db, cfg), nil)
	request := func(method, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		var body string
		if form != nil {
			body = form.Encode()
		}
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(w, r)
		return w
	}
	credentials := url.Values{"email": {"alice@example.test"}, "password": {"correct-password"}}
	if got := request(http.MethodPost, "/login", credentials); got.Code != http.StatusForbidden {
		t.Fatalf("login without CSRF status=%d", got.Code)
	}
	page := request(http.MethodGet, "/login", nil)
	if page.Code != http.StatusOK || page.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("login page status=%d cache=%q", page.Code, page.Header().Get("Cache-Control"))
	}
	match := regexp.MustCompile(`name="csrf_token" value="([a-f0-9]+)"`).FindStringSubmatch(page.Body.String())
	if len(match) != 2 {
		t.Fatal("login form has no CSRF token")
	}
	var loginCookie *http.Cookie
	for _, cookie := range page.Result().Cookies() {
		if cookie.Name == "gomail_login_csrf" {
			loginCookie = cookie
		}
	}
	if loginCookie == nil {
		t.Fatal("login page has no pre-session cookie")
	}
	secondPage := request(http.MethodGet, "/login", nil, loginCookie)
	secondMatch := regexp.MustCompile(`name="csrf_token" value="([a-f0-9]+)"`).FindStringSubmatch(secondPage.Body.String())
	if len(secondMatch) != 2 || secondMatch[1] != match[1] {
		t.Fatal("opening a second login tab invalidated the first form")
	}
	stale := request(http.MethodPost, "/login", url.Values{"email": {"alice@example.test"}, "password": {"correct-password"}, "csrf_token": {match[1]}})
	if stale.Code != http.StatusForbidden || !strings.Contains(stale.Body.String(), "sign-in form expired") || !strings.Contains(stale.Body.String(), "alice@example.test") || strings.Contains(stale.Body.String(), "correct-password") {
		t.Fatalf("stale login form did not recover safely: status=%d body=%q", stale.Code, stale.Body.String())
	}
	forged := &http.Cookie{Name: "gomail_login_csrf", Value: strings.Repeat("a", 64) + "." + strings.Repeat("b", 64)}
	if response := request(http.MethodGet, "/login", nil, forged); response.Result().Cookies()[0].Value == forged.Value {
		t.Fatal("server reused a forged login cookie")
	}
	credentials.Set("csrf_token", match[1])
	login := request(http.MethodPost, "/login", credentials, loginCookie)
	if login.Code != http.StatusSeeOther {
		t.Fatalf("valid login status=%d body=%q", login.Code, login.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, cookie := range login.Result().Cookies() {
		if cookie.Name == "gomail_session" {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil {
		t.Fatal("login created no session")
	}
	if got := request(http.MethodGet, "/logout", nil, sessionCookie); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout status=%d", got.Code)
	}
	if got := request(http.MethodPost, "/logout", nil, sessionCookie); got.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF status=%d", got.Code)
	}
	csrfRequest := httptest.NewRequest(http.MethodGet, "/inbox", nil)
	csrfRequest.AddCookie(sessionCookie)
	logout := request(http.MethodPost, "/logout", url.Values{"csrf_token": {server.sessionMgr.GenerateCSRFToken(csrfRequest)}}, sessionCookie)
	if logout.Code != http.StatusSeeOther {
		t.Fatalf("valid logout status=%d", logout.Code)
	}
	if got := request(http.MethodGet, "/inbox", nil, sessionCookie); got.Code != http.StatusSeeOther {
		t.Fatalf("logged-out session still worked: status=%d", got.Code)
	}
}

func TestDatabaseFailureDoesNotCountAsBadPassword(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Web.SessionMaxAge = 3600
	cfg.Security.CSRFKey = "csrf-test-key"
	server := NewServer(cfg, db, delivery.NewQueue(db, cfg), nil)
	page := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/login", nil))
	match := regexp.MustCompile(`name="csrf_token" value="([a-f0-9]+)"`).FindStringSubmatch(page.Body.String())
	if len(match) != 2 || len(page.Result().Cookies()) == 0 {
		t.Fatal("login form token unavailable")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		form := url.Values{"email": {"alice@example.test"}, "password": {"correct-password"}, "csrf_token": {match[1]}}
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(page.Result().Cookies()[0])
		w := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("database failure status=%d", w.Code)
		}
	}
	if len(server.loginRateLimiter.attempts) != 0 {
		t.Fatalf("database failures counted as bad passwords: %+v", server.loginRateLimiter.attempts)
	}
}
