package web

import (
	"fmt"
	"gomail/config"
	"gomail/delivery"
	"gomail/store"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestForwardHTMLPreviewIsSandboxedAndAccountScoped(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(root+"/mail.db", root+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.com'); INSERT INTO accounts(id,domain_id,email,password_hash,is_active) VALUES(1,1,'alice@example.com','test',1),(2,1,'bob@example.com','test',1)`); err != nil {
		t.Fatal(err)
	}
	id, err := db.SaveMessage(&store.Message{AccountID: 1, MessageID: "overlay-test", Direction: "inbound", FromAddr: "sender@example.net", ToAddr: "alice@example.com", Subject: "Hello", HTMLBody: `<div style="position:fixed;inset:0;z-index:999999">overlay</div><img src="https://tracker.example/pixel"><img src="cid:part1">`, ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Web.SessionMaxAge = 3600
	cfg.Security.CSRFKey = "test-key"
	server := NewServer(cfg, db, delivery.NewQueue(db, cfg), nil)
	login := httptest.NewRecorder()
	if err := server.sessionMgr.CreateSession(login, "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/forward/%d", id)
	req := httptest.NewRequest("GET", path, nil)
	req.AddCookie(login.Result().Cookies()[0])
	res := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(res, req)
	if res.Code != 200 || !strings.Contains(res.Body.String(), `sandbox=""`) || !strings.Contains(res.Body.String(), fmt.Sprintf(`/message-content/%d`, id)) || strings.Contains(res.Body.String(), "position:fixed") {
		t.Fatalf("unsafe forward preview: %d %s", res.Code, res.Body.String())
	}
	content := httptest.NewRequest("GET", fmt.Sprintf("/message-content/%d", id), nil)
	content.AddCookie(login.Result().Cookies()[0])
	contentRes := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(contentRes, content)
	if contentRes.Code != 200 || !strings.Contains(contentRes.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("HTML preview endpoint lacked isolation: %d", contentRes.Code)
	}
	if strings.Contains(contentRes.Body.String(), "tracker.example") || strings.Contains(contentRes.Header().Get("Content-Security-Policy"), "https:") || !strings.Contains(contentRes.Body.String(), "cid:part1") {
		t.Fatalf("default remote image policy failed: body=%q csp=%q", contentRes.Body.String(), contentRes.Header().Get("Content-Security-Policy"))
	}
	withoutPermit := httptest.NewRequest("GET", fmt.Sprintf("/message-content/%d?remote_images=1", id), nil)
	withoutPermit.AddCookie(login.Result().Cookies()[0])
	withoutPermitRes := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(withoutPermitRes, withoutPermit)
	if strings.Contains(withoutPermitRes.Body.String(), "tracker.example") {
		t.Fatal("bare query parameter bypassed image opt-in")
	}
	view := httptest.NewRequest("GET", fmt.Sprintf("/message/%d", id), nil)
	view.AddCookie(login.Result().Cookies()[0])
	viewRes := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(viewRes, view)
	permitMatch := regexp.MustCompile(`permit=([a-f0-9]{64})`).FindStringSubmatch(viewRes.Body.String())
	if len(permitMatch) != 2 {
		t.Fatal("message view did not issue image opt-in permit")
	}
	optIn := httptest.NewRequest("GET", fmt.Sprintf("/message-content/%d?remote_images=1&permit=%s", id, permitMatch[1]), nil)
	optIn.AddCookie(login.Result().Cookies()[0])
	optInRes := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(optInRes, optIn)
	if optInRes.Code != 200 || !strings.Contains(optInRes.Body.String(), "tracker.example") || !strings.Contains(optInRes.Header().Get("Content-Security-Policy"), "https:") {
		t.Fatal("explicit remote image opt-in failed")
	}
	bobLogin := httptest.NewRecorder()
	if err := server.sessionMgr.CreateSession(bobLogin, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	bobReq := httptest.NewRequest("GET", fmt.Sprintf("/message-content/%d", id), nil)
	bobReq.AddCookie(bobLogin.Result().Cookies()[0])
	bobRes := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(bobRes, bobReq)
	if bobRes.Code != 404 {
		t.Fatalf("cross-account preview access: %d", bobRes.Code)
	}
}
