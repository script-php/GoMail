package web

import (
	"gomail/config"
	"gomail/delivery"
	"gomail/store"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestQueueAdminAuthorizationAndActions(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(root+"/mail.db", root+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.com'); INSERT INTO accounts(id,domain_id,email,password_hash,is_admin) VALUES(1,1,'admin@example.com','test',1),(2,1,'user@example.com','test',0)`)
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.EnqueueMessage(&store.QueueEntry{MailFrom: "admin@example.com", RcptTo: "user@example.com", RawMessage: []byte("SECRET BODY"), MaxAttempts: 6, NextRetry: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Web.SessionMaxAge = 3600
	cfg.Security.CSRFKey = "test-key"
	server := NewServer(cfg, db, delivery.NewQueue(db, cfg), nil)
	login := httptest.NewRecorder()
	if err := server.sessionMgr.CreateSession(login, "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	cookie := login.Result().Cookies()[0]
	tokenReq := httptest.NewRequest("GET", "/", nil)
	tokenReq.AddCookie(cookie)
	csrf := server.sessionMgr.GenerateCSRFToken(tokenReq)
	for _, tc := range []struct {
		method, body string
		token        bool
		code         int
	}{
		{"GET", "", false, 200}, {"POST", "single=cancel:1", false, 403}, {"POST", "single=cancel:1", true, 303},
	} {
		req := httptest.NewRequest(tc.method, "/admin/queue", strings.NewReader(tc.body))
		req.AddCookie(cookie)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if tc.token {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		res := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(res, req)
		if res.Code != tc.code {
			t.Fatalf("%s: %d %s", tc.method, res.Code, res.Body.String())
		}
		if tc.method == "GET" && (!strings.Contains(res.Body.String(), "</html>") || strings.Contains(res.Body.String(), "SECRET BODY")) {
			t.Fatal("incomplete or unsafe queue rendering")
		}
	}
	status, err := db.QueueEntryStatus(id)
	if err != nil || status != "cancelled" {
		t.Fatalf("status %s: %v", status, err)
	}
	historyReq := httptest.NewRequest("GET", "/admin/queue?history=1", nil)
	historyReq.AddCookie(cookie)
	historyRes := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(historyRes, historyReq)
	if historyRes.Code != 200 || !strings.Contains(historyRes.Body.String(), "admin_cancel") || strings.Contains(historyRes.Body.String(), "SECRET BODY") {
		t.Fatalf("unsafe or missing delivery history: %d", historyRes.Code)
	}
	login = httptest.NewRecorder()
	if err := server.sessionMgr.CreateSession(login, "user@example.com"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/admin/queue", nil)
	req.AddCookie(login.Result().Cookies()[0])
	res := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(res, req)
	if res.Code == 200 {
		t.Fatal("non-admin accessed queue")
	}
}

func TestQueueAdminVERPRetentionSetting(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(root+"/mail.db", root+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.com'); INSERT INTO accounts(id,domain_id,email,password_hash,is_admin) VALUES(1,1,'admin@example.com','test',1)`); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Web.SessionMaxAge = 3600
	cfg.Security.CSRFKey = "test-key"
	server := NewServer(cfg, db, delivery.NewQueue(db, cfg), nil)
	login := httptest.NewRecorder()
	if err := server.sessionMgr.CreateSession(login, "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	cookie := login.Result().Cookies()[0]
	tokenReq := httptest.NewRequest("GET", "/admin/queue", nil)
	tokenReq.AddCookie(cookie)
	csrf := server.sessionMgr.GenerateCSRFToken(tokenReq)
	form := url.Values{"action": {"verp_retention_save"}, "verp_retention_days": {"90"}, "csrf_token": {csrf}}
	req := httptest.NewRequest("POST", "/admin/queue", strings.NewReader(form.Encode()))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(res, req)
	if res.Code != 303 {
		t.Fatalf("save VERP retention: %d %s", res.Code, res.Body.String())
	}
	if days, err := db.VERPRetentionDays(); err != nil || days != 90 {
		t.Fatalf("VERP retention not saved: %d %v", days, err)
	}
	page := httptest.NewRecorder()
	get := httptest.NewRequest("GET", "/admin/queue", nil)
	get.AddCookie(cookie)
	server.httpServer.Handler.ServeHTTP(page, get)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "value=\"90\"") || !strings.Contains(page.Body.String(), "Archived bounce-address retention") {
		t.Fatalf("retention form missing: status=%d value=%t section=%t", page.Code, strings.Contains(page.Body.String(), "value=\"90\""), strings.Contains(page.Body.String(), "Archived bounce-address retention"))
	}
}
