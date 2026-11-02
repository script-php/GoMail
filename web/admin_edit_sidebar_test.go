package web

import (
	"gomail/config"
	"gomail/delivery"
	"gomail/store"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminEditPagesKeepAdminSidebar(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(root+"/mail.db", root+"/attachments")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.com'); INSERT INTO accounts(id,domain_id,email,password_hash,is_admin,is_active) VALUES(1,1,'admin@example.com','test',1,1)`); err != nil {
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
	for _, tc := range []struct{ path, active string }{
		{"/admin/domain/edit/1", "domains"},
		{"/admin/domain/edit/new", "domains"},
		{"/admin/account/edit/1", "accounts"},
		{"/admin/account/edit/new", "accounts"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, nil)
			req.AddCookie(cookie)
			res := httptest.NewRecorder()
			server.httpServer.Handler.ServeHTTP(res, req)
			body := res.Body.String()
			activeLink := `<li class="active">` + "\n" + `                <a href="/admin/` + tc.active + `">`
			if res.Code != 200 || !strings.Contains(body, `href="/admin/configuration"`) || !strings.Contains(body, activeLink) || strings.Contains(body, `class="compose-btn"`) {
				t.Fatalf("edit page did not keep admin sidebar: %s (%d)", tc.path, res.Code)
			}
		})
	}
}
