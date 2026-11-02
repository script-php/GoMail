package web

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gomail/config"
	"gomail/delivery"
	"gomail/store"
)

func TestWebmailRoutesAndIsolation(t *testing.T) {
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetMaxOpenConns(1)
	schema, err := os.ReadFile("../store/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(string(schema)); err != nil {
		t.Fatal(err)
	}
	db := &store.DB{DB: conn}
	if _, err = conn.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.com'); INSERT INTO accounts(id,domain_id,email,password_hash,is_active) VALUES(1,1,'one@example.com','test',1),(2,1,'two@example.com','test',1)`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{1, 2} {
		if err = db.DefaultFolders(id); err != nil {
			t.Fatal(err)
		}
	}
	folder, _ := db.GetFolderByType(1, "inbox")
	own, err := db.SaveMessage(&store.Message{AccountID: 1, FolderID: &folder.ID, MessageID: "one", Direction: "inbound", Subject: "Needle", ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	other, err := db.SaveMessage(&store.Message{AccountID: 2, MessageID: "two", Direction: "inbound", Subject: "Private", ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if own != 1 || other != 2 {
		t.Fatal("unexpected test IDs")
	}
	sentFolder, _ := db.GetFolderByType(1, "sent")
	if _, err := db.SaveMessage(&store.Message{AccountID: 1, FolderID: &sentFolder.ID, MessageID: "sent", Direction: "outbound", FromAddr: "one@example.com", ToAddr: "recipient@example.net", Subject: "Needle sent", ReceivedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Web.SessionMaxAge = 3600
	cfg.Security.CSRFKey = "test-key"
	server := NewServer(cfg, db, delivery.NewQueue(db, cfg), nil)
	login := httptest.NewRecorder()
	if err := server.sessionMgr.CreateSession(login, "one@example.com"); err != nil {
		t.Fatal(err)
	}
	cookie := login.Result().Cookies()[0]
	tokenRequest := httptest.NewRequest("GET", "/", nil)
	tokenRequest.AddCookie(cookie)
	csrf := server.sessionMgr.GenerateCSRFToken(tokenRequest)
	forwardBody := "original_message_id=1&to=outside%40example.net&subject=Fwd%3A+Needle&forward_notes=hello"
	forwardRequest := httptest.NewRequest("POST", "/forward-send", strings.NewReader(forwardBody))
	forwardRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	forwardRequest.Header.Set("X-CSRF-Token", csrf)
	forwardRequest.AddCookie(cookie)
	forwardResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(forwardResponse, forwardRequest)
	if forwardResponse.Code != http.StatusUnprocessableEntity || !strings.Contains(forwardResponse.Body.String(), "DKIM is not configured") || !strings.Contains(forwardResponse.Body.String(), "value=\"outside@example.net\"") {
		t.Fatalf("forward error was not actionable/preserved: %d %s", forwardResponse.Code, forwardResponse.Body.String())
	}
	for _, tc := range []struct {
		method, path, body string
		csrf               bool
		status             int
	}{
		{"GET", "/search?q=Needle", "", false, 200},
		{"GET", "/inbox", "", false, 200},
		{"GET", "/starred", "", false, 200},
		{"GET", "/message/1", "", false, 200},
		{"GET", "/settings", "", false, 200},
		{"POST", "/message/star/1", "", false, 403},
		{"POST", "/message/star/1", "", true, 200},
		{"POST", "/message/delete/2", "", true, 404},
		{"POST", "/api/mark-read/2", "", true, 404},
		{"POST", "/api/messages/action", `{"ids":[1,2],"action":"trash"}`, true, 400},
		{"POST", "/api/messages/action", `{"ids":[1],"action":"trash"}`, true, 200},
		{"POST", "/api/messages/action", `{"ids":[1],"action":"restore"}`, true, 200},
		{"POST", "/message/delete/1", "", true, 303},
		{"POST", "/message/permanent-delete/1", "", true, 303},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.AddCookie(cookie)
		req.Header.Set("Content-Type", "application/json")
		if tc.csrf {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, req)
		if response.Code != tc.status {
			t.Errorf("%s %s: got %d: %s", tc.method, tc.path, response.Code, response.Body.String())
		}
		if tc.method == "GET" && response.Code == 200 && !strings.Contains(response.Body.String(), "</html>") {
			t.Fatalf("incomplete page: %s", tc.path)
		}
		if tc.path == "/search?q=Needle" && (!strings.Contains(response.Body.String(), "Needle") || strings.Contains(response.Body.String(), "Private") || !strings.Contains(response.Body.String(), "Received") || !strings.Contains(response.Body.String(), "Sent") || !strings.Contains(response.Body.String(), "To: recipient@example.net")) {
			t.Fatal("bad search rendering")
		}
	}
	settingsRequest := httptest.NewRequest("POST", "/settings", strings.NewReader("display_name=Mailbox+Owner"))
	settingsRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	settingsRequest.Header.Set("X-CSRF-Token", csrf)
	settingsRequest.AddCookie(cookie)
	settingsResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(settingsResponse, settingsRequest)
	if settingsResponse.Code != http.StatusOK {
		t.Fatalf("settings update: %d %s", settingsResponse.Code, settingsResponse.Body.String())
	}
	updated, _ := db.GetAccount(1)
	if updated == nil || updated.DisplayName != "Mailbox Owner" {
		t.Fatalf("profile was not updated: %+v", updated)
	}
	oldHash, _ := bcrypt.GenerateFromPassword([]byte("current-password"), bcrypt.DefaultCost)
	if err := db.UpdateAccountPassword(1, string(oldHash)); err != nil {
		t.Fatal(err)
	}
	login = httptest.NewRecorder()
	if err := server.sessionMgr.CreateSession(login, "one@example.com"); err != nil {
		t.Fatal(err)
	}
	cookie = login.Result().Cookies()[0]
	tokenRequest = httptest.NewRequest("GET", "/", nil)
	tokenRequest.AddCookie(cookie)
	csrf = server.sessionMgr.GenerateCSRFToken(tokenRequest)
	passwordForm := "display_name=Mailbox+Owner&current_password=current-password&new_password=new-password-123&confirm_password=new-password-123"
	passwordRequest := httptest.NewRequest("POST", "/settings", strings.NewReader(passwordForm))
	passwordRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	passwordRequest.Header.Set("X-CSRF-Token", csrf)
	passwordRequest.AddCookie(cookie)
	passwordResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(passwordResponse, passwordRequest)
	if passwordResponse.Code != http.StatusSeeOther || passwordResponse.Header().Get("Location") != "/login" {
		t.Fatalf("password update: %d %s", passwordResponse.Code, passwordResponse.Body.String())
	}
	updated, _ = db.GetAccount(1)
	if bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte("new-password-123")) != nil {
		t.Fatal("password was not updated")
	}
	if _, err = conn.Exec(`UPDATE accounts SET is_active=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/inbox", nil)
	req.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, req)
	if response.Code != http.StatusSeeOther {
		t.Fatal("disabled account kept access")
	}
}

func TestReadinessFailsUnderDiskPressure(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(root+"/mail.db", root+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.ConfigureDiskPressure(1<<62+1, 1<<62, root)
	cfg := &config.Config{}
	cfg.Security.CSRFKey = "test-key"
	server := NewServer(cfg, db, delivery.NewQueue(db, cfg), nil)
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "storage") {
		t.Fatalf("readiness status=%d body=%s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response = httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("liveness was incorrectly degraded: %d", response.Code)
	}
}
