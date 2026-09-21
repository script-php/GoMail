package web

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

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
	for _, tc := range []struct {
		method, path, body string
		csrf               bool
		status             int
	}{
		{"GET", "/search?q=Needle", "", false, 200},
		{"GET", "/inbox", "", false, 200},
		{"GET", "/message/1", "", false, 200},
		{"POST", "/message/star/1", "", false, 403},
		{"POST", "/message/star/1", "", true, 200},
		{"POST", "/message/delete/2", "", true, 404},
		{"POST", "/api/mark-read/2", "", true, 404},
		{"POST", "/api/messages/action", `{"ids":[1,2],"action":"trash"}`, true, 400},
		{"POST", "/api/messages/action", `{"ids":[1],"action":"trash"}`, true, 200},
		{"POST", "/api/messages/action", `{"ids":[1],"action":"restore"}`, true, 200},
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
		if tc.path == "/search?q=Needle" && (!strings.Contains(response.Body.String(), "Needle") || strings.Contains(response.Body.String(), "Private")) {
			t.Fatal("bad search rendering")
		}
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
