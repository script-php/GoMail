package web

import (
	"encoding/json"
	"gomail/backup"
	"gomail/config"
	"gomail/delivery"
	"gomail/store"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminConfigurationFormAndJSONViews(t *testing.T) {
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
	cfg.Server.Hostname = "mail.example.com"
	cfg.Web.SessionSecret = "private-session-secret"
	cfg.Web.SessionMaxAge = 3600
	cfg.Security.CSRFKey = "private-csrf-secret"
	path := filepath.Join(root, "config.json")
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	manager := backup.NewManager(cfg, db, path, "test")
	server := NewServer(cfg, db, delivery.NewQueue(db, cfg), nil, manager)
	login := httptest.NewRecorder()
	if err := server.sessionMgr.CreateSession(login, "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	cookie := login.Result().Cookies()[0]
	request := func(method, target string, body url.Values) *httptest.ResponseRecorder {
		t.Helper()
		var raw string
		if body != nil {
			raw = body.Encode()
		}
		req := httptest.NewRequest(method, target, strings.NewReader(raw))
		req.AddCookie(cookie)
		if body != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-CSRF-Token", server.sessionMgr.GenerateCSRFToken(req))
		}
		res := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(res, req)
		return res
	}
	formPage := request("GET", "/admin/configuration", nil)
	if formPage.Code != 200 || !strings.Contains(formPage.Body.String(), `name="field.server.hostname"`) || strings.Contains(formPage.Body.String(), "private-session-secret") {
		t.Fatalf("unsafe or missing form view: %d", formPage.Code)
	}
	jsonPage := request("GET", "/admin/configuration?view=json", nil)
	if jsonPage.Code != 200 || !strings.Contains(jsonPage.Body.String(), `name="configuration"`) || !strings.Contains(jsonPage.Body.String(), config.SecretPlaceholder) || strings.Contains(jsonPage.Body.String(), "private-session-secret") {
		t.Fatalf("unsafe or missing JSON view: %d", jsonPage.Code)
	}
	redacted, _ := config.EditableJSON(cfg)
	sections, err := config.EditableFormSections(redacted)
	if err != nil {
		t.Fatal(err)
	}
	values := url.Values{"view": {"form"}, "action": {"validate"}}
	for _, section := range sections {
		for _, field := range section.Fields {
			values.Set("field."+field.Path, field.Value)
		}
	}
	values.Set("field.server.hostname", "new.example.com")
	validated := request("POST", "/admin/configuration", values)
	if validated.Code != 200 || !strings.Contains(validated.Body.String(), "Configuration is valid") {
		t.Fatalf("form validation failed: %d %s", validated.Code, validated.Body.String())
	}
	unchanged, err := config.Load(path)
	if err != nil || unchanged.Server.Hostname != "mail.example.com" {
		t.Fatal("validate action wrote configuration")
	}
	values.Set("action", "save")
	saved := request("POST", "/admin/configuration", values)
	if saved.Code != http.StatusSeeOther || saved.Header().Get("Location") != "/admin/configuration?saved=1&view=form" {
		t.Fatalf("form save failed: %d %s", saved.Code, saved.Body.String())
	}
	updated, err := config.Load(path)
	if err != nil || updated.Server.Hostname != "new.example.com" || updated.Web.SessionSecret != "private-session-secret" {
		t.Fatalf("saved config lost values: %+v %v", updated, err)
	}
}
