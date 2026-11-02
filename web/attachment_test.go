package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gomail/config"
	"gomail/delivery"
	"gomail/store"
)

func TestAttachmentDownloadRequiresMessageOwnership(t *testing.T) {
	root := t.TempDir()
	attachmentsRoot := filepath.Join(root, "attachments")
	db, err := store.Open(filepath.Join(root, "mail.db"), attachmentsRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	domainID, err := db.CreateDomain(&store.Domain{Domain: "example.com", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	aliceID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "alice@example.com", PasswordHash: "test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	bobID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "bob@example.com", PasswordHash: "test", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	bobInbox, err := db.GetFolderByType(bobID, "inbox")
	if err != nil || bobInbox == nil {
		t.Fatalf("Bob Inbox: %v", err)
	}
	bobMessageID, err := db.SaveMessage(&store.Message{
		AccountID: bobID, FolderID: &bobInbox.ID, MessageID: "private", Direction: "inbound",
		RawMessage: []byte("Subject: private\r\n\r\nsecret\r\n"), ReceivedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	const secret = "bob-only-attachment"
	if err := os.WriteFile(filepath.Join(attachmentsRoot, "bob-secret.txt"), []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	attachmentID, err := db.SaveAttachment(&store.Attachment{
		MessageID: bobMessageID, Filename: "secret.txt", ContentType: "text/plain",
		Size: int64(len(secret)), StoragePath: "bob-secret.txt",
	})
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
	cookie := login.Result().Cookies()[0]

	request := httptest.NewRequest(http.MethodGet, "/attachment/"+formatID(attachmentID), nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("Alice fetched Bob's attachment: status=%d body=%q", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), secret) {
		t.Fatal("cross-account response exposed attachment bytes")
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("authenticated attachment response may be cached")
	}
	bobLogin := httptest.NewRecorder()
	if err := server.sessionMgr.CreateSession(bobLogin, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	bobRequest := httptest.NewRequest(http.MethodGet, "/attachment/"+formatID(attachmentID), nil)
	bobRequest.AddCookie(bobLogin.Result().Cookies()[0])
	bobResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(bobResponse, bobRequest)
	if bobResponse.Code != http.StatusOK || bobResponse.Body.String() != secret || bobResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("owned attachment status=%d cache=%q body=%q", bobResponse.Code, bobResponse.Header().Get("Cache-Control"), bobResponse.Body.String())
	}
	outside := filepath.Join(root, "outside-secret.txt")
	if err := os.WriteFile(outside, []byte("outside-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(attachmentsRoot, "bob-secret.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(attachmentsRoot, "bob-secret.txt")); err != nil {
		t.Fatal(err)
	}
	symlinkRequest := httptest.NewRequest(http.MethodGet, "/attachment/"+formatID(attachmentID), nil)
	symlinkRequest.AddCookie(bobLogin.Result().Cookies()[0])
	symlinkResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(symlinkResponse, symlinkRequest)
	if symlinkResponse.Code != http.StatusNotFound || strings.Contains(symlinkResponse.Body.String(), "outside-secret") {
		t.Fatalf("symlink escaped attachment root: status=%d body=%q", symlinkResponse.Code, symlinkResponse.Body.String())
	}

	if attachment, err := db.GetAttachmentForAccount(attachmentID, aliceID); err != nil || attachment != nil {
		t.Fatalf("scoped lookup exposed Bob attachment: attachment=%+v err=%v", attachment, err)
	}
}

func formatID(id int64) string {
	return strconv.FormatInt(id, 10)
}
