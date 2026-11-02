package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gomail/config"
	"gomail/delivery"
	"gomail/store"
)

func TestReceivedReportsAdminIsDisabledUntilMailboxSelected(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(root+"/mail.db", root+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.test'); INSERT INTO accounts(id,domain_id,email,password_hash,is_admin,is_active) VALUES(1,1,'admin@example.test','unused',1,1)`); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Web: config.WebConfig{SessionMaxAge: 3600}, Security: config.SecurityConfig{CSRFKey: "report-test-key"}}
	server := NewServer(cfg, db, delivery.NewQueue(db, cfg), nil)
	login := httptest.NewRecorder()
	if err := server.sessionMgr.CreateSession(login, "admin@example.test"); err != nil {
		t.Fatal(err)
	}
	cookie := login.Result().Cookies()[0]
	request := func(method string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		var body string
		if form != nil {
			body = form.Encode()
		}
		req := httptest.NewRequest(method, "/admin/received-reports", strings.NewReader(body))
		req.AddCookie(cookie)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-CSRF-Token", server.sessionMgr.GenerateCSRFToken(req))
		}
		res := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(res, req)
		return res
	}
	page := request(http.MethodGet, nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Analyzer off") || !strings.Contains(page.Body.String(), "admin@example.test") {
		t.Fatalf("initial page status=%d body=%s", page.Code, page.Body.String())
	}
	bad := request(http.MethodPost, url.Values{"action": {"save"}, "enabled": {"on"}, "account_id": {"0"}})
	if bad.Code != http.StatusOK || !strings.Contains(bad.Body.String(), "select a local report mailbox") {
		t.Fatalf("invalid mailbox accepted: %d", bad.Code)
	}
	saved := request(http.MethodPost, url.Values{"action": {"save"}, "enabled": {"on"}, "account_id": {"1"}})
	if saved.Code != http.StatusSeeOther {
		t.Fatalf("save response=%d body=%s", saved.Code, saved.Body.String())
	}
	settings, err := db.GetReportInboxSettings()
	if err != nil || !settings.Enabled || settings.AccountID != 1 {
		t.Fatalf("settings=%+v err=%v", settings, err)
	}
	denied := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(denied, httptest.NewRequest(http.MethodGet, "/admin/received-reports", nil))
	if denied.Code == http.StatusOK {
		t.Fatal("unauthenticated report dashboard was accessible")
	}
}
