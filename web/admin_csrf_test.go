package web

import (
	"gomail/config"
	"gomail/delivery"
	"gomail/store"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminGreylistingAndTarpittingRequireCSRF(t *testing.T) {
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
	for _, path := range []string{"/admin/greylisting?domain=1", "/admin/tarpitting?domain=1"} {
		for _, token := range []string{"", "incorrect-token"} {
			req := httptest.NewRequest("POST", path, strings.NewReader("action=delete&entry_id=1"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if token != "" {
				req.Header.Set("X-CSRF-Token", token)
			}
			req.AddCookie(cookie)
			res := httptest.NewRecorder()
			server.httpServer.Handler.ServeHTTP(res, req)
			if res.Code != 403 {
				t.Errorf("%s with token %q: got %d, want 403", path, token, res.Code)
			}
		}
	}
}
