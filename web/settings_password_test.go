package web

import (
	"gomail/config"
	"gomail/delivery"
	"gomail/store"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestPasswordChangeRevokesAllWebSessions(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(root+"/mail.db", root+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hash, err := bcrypt.GenerateFromPassword([]byte("current-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.com'); INSERT INTO accounts(id,domain_id,email,password_hash,is_active) VALUES(1,1,'alice@example.com',?,1)`, string(hash)); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Web.SessionMaxAge = 3600
	cfg.Security.CSRFKey = "test-key"
	server := NewServer(cfg, db, delivery.NewQueue(db, cfg), nil)
	cookies := make([]*http.Cookie, 2)
	for i := range cookies {
		login := httptest.NewRecorder()
		if err := server.sessionMgr.CreateSession(login, "alice@example.com"); err != nil {
			t.Fatal(err)
		}
		cookies[i] = login.Result().Cookies()[0]
	}
	tokenReq := httptest.NewRequest("GET", "/settings", nil)
	tokenReq.AddCookie(cookies[0])
	form := url.Values{"display_name": {"Alice"}, "current_password": {"current-password"}, "new_password": {"new-password-123"}, "confirm_password": {"new-password-123"}}
	req := httptest.NewRequest("POST", "/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", server.sessionMgr.GenerateCSRFToken(tokenReq))
	req.AddCookie(cookies[0])
	res := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(res, req)
	if res.Code != http.StatusSeeOther || res.Header().Get("Location") != "/login" {
		t.Fatalf("password change response: %d %s", res.Code, res.Body.String())
	}
	for _, cookie := range cookies {
		request := httptest.NewRequest("GET", "/inbox", nil)
		request.AddCookie(cookie)
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
			t.Fatalf("old session remained active: %d", response.Code)
		}
	}
}
