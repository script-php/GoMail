package web

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gomail/auth"
	"gomail/config"
	"gomail/delivery"
	"gomail/store"
)

func TestWebmailOriginatedAndForwardedHeaders(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	private, public, _, err := auth.GenerateDKIMKeyPair("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	domainID, err := db.CreateDomain(&store.Domain{Domain: "sender.example", IsActive: true, DKIMSelector: "mail", DKIMAlgorithm: "ed25519", DKIMPrivateKey: private, DKIMPublicKey: public})
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := db.CreateAccount(&store.Account{DomainID: domainID, Email: "alice@sender.example", IsActive: true, PasswordHash: "test"})
	if err != nil {
		t.Fatal(err)
	}
	originalRaw := []byte("From: original@remote.example\r\nTo: alice@sender.example\r\nSubject: Original\r\nX-Exact: folded\r\n\tvalue\r\n\r\nOriginal body\r\n.dot line\r\n")
	originalID, err := db.SaveMessage(&store.Message{
		AccountID: accountID, MessageID: "original@remote.example", Direction: "inbound",
		FromAddr: "original@remote.example", ToAddr: "alice@sender.example", Subject: "Original",
		TextBody: "Original body", RawMessage: originalRaw,
		ReceivedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Server: config.ServerConfig{Hostname: "mail.sender.example", Domain: "sender.example"}}
	cfg.Web.SessionMaxAge = 3600
	cfg.Security.CSRFKey = "test-key"
	server := NewServer(cfg, db, delivery.NewQueue(db, cfg), nil)
	login := httptest.NewRecorder()
	if err := server.sessionMgr.CreateSession(login, "alice@sender.example"); err != nil {
		t.Fatal(err)
	}
	cookie := login.Result().Cookies()[0]
	tokenRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	tokenRequest.AddCookie(cookie)
	csrf := server.sessionMgr.GenerateCSRFToken(tokenRequest)

	post := func(path string, values url.Values) {
		t.Helper()
		var request *http.Request
		if path == "/send" {
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			for key, items := range values {
				for _, item := range items {
					if err := writer.WriteField(key, item); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			request = httptest.NewRequest(http.MethodPost, path, &body)
			request.Header.Set("Content-Type", writer.FormDataContentType())
		} else {
			request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		request.Header.Set("X-CSRF-Token", csrf)
		request.AddCookie(cookie)
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		if response.Code != http.StatusSeeOther {
			t.Fatalf("%s: status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
	post("/send", url.Values{"to": {"compose@receiver.example"}, "subject": {"New message"}, "body": {"Hello"}})
	post("/forward-send", url.Values{"original_message_id": {strconv.FormatInt(originalID, 10)}, "to": {"forward@receiver.example"}, "subject": {"Fwd: Original"}, "forward_notes": {"FYI"}})

	queued := func(recipient string) string {
		t.Helper()
		var raw []byte
		if err := db.QueryRow(`SELECT raw_message FROM outbound_queue WHERE rcpt_to = ?`, recipient).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	compose := queued("compose@receiver.example")
	if strings.Contains(strings.ToLower(compose), "\r\nreturn-path:") || strings.HasPrefix(strings.ToLower(compose), "return-path:") {
		t.Fatal("originating webmail message set Return-Path before final delivery")
	}
	forward := queued("forward@receiver.example")
	for _, forbidden := range []string{"\r\nResent-", "\r\nReply-To: original@remote.example", "\r\nReturn-Path:"} {
		if strings.Contains(forward, forbidden) {
			t.Fatalf("new forward contains inappropriate header %q", forbidden)
		}
	}
	if !strings.Contains(forward, "From: alice@sender.example\r\n") || !strings.Contains(forward, "original@remote.example") {
		t.Fatal("forward lost its sender or original-message context")
	}
	message, err := mail.ReadMessage(strings.NewReader(forward))
	if err != nil {
		t.Fatal(err)
	}
	_, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	parts := multipart.NewReader(message.Body, params["boundary"])
	if _, err := parts.NextPart(); err != nil {
		t.Fatal(err)
	}
	attachment, err := parts.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	attachedRaw, err := io.ReadAll(attachment)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(attachedRaw, originalRaw) {
		t.Fatalf("forward changed source MIME bytes: got %q want %q", attachedRaw, originalRaw)
	}

	malformedID, err := db.SaveMessage(&store.Message{AccountID: accountID, MessageID: "lf-only@remote.example", Direction: "inbound", FromAddr: "original@remote.example", ToAddr: "alice@sender.example", Subject: "Malformed", RawMessage: []byte("From: original@remote.example\n\nbody"), ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"original_message_id": {strconv.FormatInt(malformedID, 10)}, "to": {"forward@receiver.example"}, "subject": {"Fwd: Malformed"}}
	malformedRequest := httptest.NewRequest(http.MethodPost, "/forward-send", strings.NewReader(form.Encode()))
	malformedRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	malformedRequest.Header.Set("X-CSRF-Token", csrf)
	malformedRequest.AddCookie(cookie)
	malformedResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(malformedResponse, malformedRequest)
	if malformedResponse.Code != http.StatusUnprocessableEntity {
		t.Fatalf("malformed source accepted: %d", malformedResponse.Code)
	}
	var queuedCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM outbound_queue WHERE rcpt_to=?`, "forward@receiver.example").Scan(&queuedCount); err != nil || queuedCount != 1 {
		t.Fatalf("malformed forward queued: count=%d err=%v", queuedCount, err)
	}
}
