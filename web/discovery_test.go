package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gomail/config"
)

func boolPointer(value bool) *bool { return &value }

func discoveryTestServer(enabled bool) *Server {
	cfg := &config.Config{
		Server: config.ServerConfig{Hostname: "mail.example.com", Domain: "example.com"},
		TLS:    config.TLSConfig{Mode: "manual", CertFile: "certificate.pem", KeyFile: "key.pem"},
		Clients: config.MailClientsConfig{
			Enabled:    enabled,
			IMAP:       config.ClientServiceConfig{Enabled: boolPointer(true), ListenAddr: ":993"},
			POP3:       config.ClientServiceConfig{Enabled: boolPointer(false), ListenAddr: ":995"},
			Submission: config.ClientServiceConfig{Enabled: boolPointer(true), ListenAddr: ":587"},
		},
	}
	server := &Server{cfg: cfg}
	mux := http.NewServeMux()
	server.registerRoutes(mux)
	server.httpServer = &http.Server{Handler: mux}
	return server
}

func TestThunderbirdAutoconfigAdvertisesOnlyEnabledTLSProtocols(t *testing.T) {
	server := discoveryTestServer(true)
	request := httptest.NewRequest(http.MethodGet, "/mail/config-v1.1.xml?emailaddress=user%40example.com", nil)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, `<incomingServer type="imap">`) || !strings.Contains(body, "<port>993</port>") || !strings.Contains(body, `<outgoingServer type="smtp">`) || strings.Contains(body, `type="pop3"`) {
		t.Fatalf("autoconfig status=%d body=%s", response.Code, body)
	}
	if response.Header().Get("Content-Type") != "application/xml; charset=utf-8" {
		t.Fatalf("content type=%q", response.Header().Get("Content-Type"))
	}
}

func TestDiscoveryIsUnavailableWhenClientsOrTLSAreDisabled(t *testing.T) {
	server := discoveryTestServer(false)
	request := httptest.NewRequest(http.MethodGet, "/mail/config-v1.1.xml?emailaddress=user%40example.com", nil)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled clients status=%d", response.Code)
	}
	server = discoveryTestServer(true)
	server.cfg.TLS.Mode = "none"
	response = httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled TLS status=%d", response.Code)
	}
}

func TestAutodiscoverReturnsIMAPAndSubmission(t *testing.T) {
	server := discoveryTestServer(true)
	body := `<?xml version="1.0"?><Autodiscover><Request><EMailAddress>user@example.com</EMailAddress></Request></Autodiscover>`
	request := httptest.NewRequest(http.MethodPost, "/autodiscover/autodiscover.xml", strings.NewReader(body))
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	result := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(result, "<Type>IMAP</Type>") || !strings.Contains(result, "<SSL>on</SSL>") || !strings.Contains(result, "<Type>SMTP</Type>") || !strings.Contains(result, "<Encryption>TLS</Encryption>") || strings.Contains(result, "<Type>POP3</Type>") {
		t.Fatalf("autodiscover status=%d body=%s", response.Code, result)
	}
}

func TestDiscoveryRejectsForeignDomainAndOversizedOrMalformedInput(t *testing.T) {
	server := discoveryTestServer(true)
	request := httptest.NewRequest(http.MethodGet, "/mail/config-v1.1.xml?emailaddress=user%40other.example", nil)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("foreign autoconfig status=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/autodiscover/autodiscover.xml", strings.NewReader("<broken>"))
	response = httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("malformed autodiscover status=%d", response.Code)
	}
}
