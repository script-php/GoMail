package web

import (
	"encoding/xml"
	"net/http"
	"net/mail"
	"strconv"
	"strings"

	"gomail/config"
)

const maxAutodiscoverRequest = 64 << 10

type thunderbirdConfig struct {
	XMLName  xml.Name                 `xml:"clientConfig"`
	Version  string                   `xml:"version,attr"`
	Provider thunderbirdEmailProvider `xml:"emailProvider"`
}

type thunderbirdEmailProvider struct {
	ID       string              `xml:"id,attr"`
	Domain   string              `xml:"domain"`
	Name     string              `xml:"displayName"`
	Short    string              `xml:"displayShortName"`
	Incoming []thunderbirdServer `xml:"incomingServer"`
	Outgoing []thunderbirdServer `xml:"outgoingServer"`
}

type thunderbirdServer struct {
	Type           string `xml:"type,attr"`
	Hostname       string `xml:"hostname"`
	Port           int    `xml:"port"`
	SocketType     string `xml:"socketType"`
	Authentication string `xml:"authentication"`
	Username       string `xml:"username"`
}

type autodiscoverRequest struct {
	Request struct {
		Email string `xml:"EMailAddress"`
	} `xml:"Request"`
}

type autodiscoverResponse struct {
	XMLName xml.Name          `xml:"Autodiscover"`
	Xmlns   string            `xml:"xmlns,attr"`
	Reply   autodiscoverReply `xml:"Response"`
}

type autodiscoverReply struct {
	Xmlns   string              `xml:"xmlns,attr"`
	Account autodiscoverAccount `xml:"Account"`
}

type autodiscoverAccount struct {
	Type      string                 `xml:"AccountType"`
	Action    string                 `xml:"Action"`
	Protocols []autodiscoverProtocol `xml:"Protocol"`
}

type autodiscoverProtocol struct {
	Type         string `xml:"Type"`
	Server       string `xml:"Server"`
	Port         int    `xml:"Port"`
	LoginName    string `xml:"LoginName"`
	SSL          string `xml:"SSL"`
	Encryption   string `xml:"Encryption,omitempty"`
	AuthRequired string `xml:"AuthRequired"`
	SPA          string `xml:"SPA"`
}

func (s *Server) thunderbirdAutoconfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := strings.TrimSpace(r.URL.Query().Get("emailaddress"))
	domain, allowed := s.discoveryEmailDomain(email)
	if !s.discoveryAvailable() || !allowed {
		http.NotFound(w, r)
		return
	}
	provider := thunderbirdEmailProvider{ID: domain, Domain: domain, Name: "GoMail", Short: "GoMail"}
	if s.cfg.Clients.IMAP.IsEnabled(true) {
		provider.Incoming = append(provider.Incoming, thunderbirdServer{Type: "imap", Hostname: s.cfg.Server.Hostname, Port: listenerPort(s.cfg.Clients.IMAP.ListenAddr, 993), SocketType: "SSL", Authentication: "password-cleartext", Username: "%EMAILADDRESS%"})
	}
	if s.cfg.Clients.POP3.IsEnabled(true) {
		provider.Incoming = append(provider.Incoming, thunderbirdServer{Type: "pop3", Hostname: s.cfg.Server.Hostname, Port: listenerPort(s.cfg.Clients.POP3.ListenAddr, 995), SocketType: "SSL", Authentication: "password-cleartext", Username: "%EMAILADDRESS%"})
	}
	if s.cfg.Clients.Submission.IsEnabled(true) {
		provider.Outgoing = append(provider.Outgoing, thunderbirdServer{Type: "smtp", Hostname: s.cfg.Server.Hostname, Port: listenerPort(s.cfg.Clients.Submission.ListenAddr, 587), SocketType: "STARTTLS", Authentication: "password-cleartext", Username: "%EMAILADDRESS%"})
	}
	writeDiscoveryXML(w, thunderbirdConfig{Version: "1.1", Provider: provider})
}

func (s *Server) autodiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.discoveryAvailable() {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAutodiscoverRequest)
	decoder := xml.NewDecoder(r.Body)
	decoder.Strict = true
	var request autodiscoverRequest
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid autodiscover request", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(request.Request.Email)
	if _, allowed := s.discoveryEmailDomain(email); !allowed {
		http.Error(w, "invalid autodiscover request", http.StatusBadRequest)
		return
	}
	account := autodiscoverAccount{Type: "email", Action: "settings"}
	if s.cfg.Clients.IMAP.IsEnabled(true) {
		account.Protocols = append(account.Protocols, autodiscoverProtocol{Type: "IMAP", Server: s.cfg.Server.Hostname, Port: listenerPort(s.cfg.Clients.IMAP.ListenAddr, 993), LoginName: email, SSL: "on", AuthRequired: "on", SPA: "off"})
	}
	if s.cfg.Clients.POP3.IsEnabled(true) {
		account.Protocols = append(account.Protocols, autodiscoverProtocol{Type: "POP3", Server: s.cfg.Server.Hostname, Port: listenerPort(s.cfg.Clients.POP3.ListenAddr, 995), LoginName: email, SSL: "on", AuthRequired: "on", SPA: "off"})
	}
	if s.cfg.Clients.Submission.IsEnabled(true) {
		account.Protocols = append(account.Protocols, autodiscoverProtocol{Type: "SMTP", Server: s.cfg.Server.Hostname, Port: listenerPort(s.cfg.Clients.Submission.ListenAddr, 587), LoginName: email, SSL: "off", Encryption: "TLS", AuthRequired: "on", SPA: "off"})
	}
	writeDiscoveryXML(w, autodiscoverResponse{Xmlns: "http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006", Reply: autodiscoverReply{Xmlns: "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a", Account: account}})
}

func (s *Server) discoveryAvailable() bool {
	if !s.cfg.Clients.Enabled || !discoveryTLSConfigured(s.cfg) || strings.TrimSpace(s.cfg.Server.Hostname) == "" {
		return false
	}
	return s.cfg.Clients.IMAP.IsEnabled(true) || s.cfg.Clients.POP3.IsEnabled(true) || s.cfg.Clients.Submission.IsEnabled(true)
}

func discoveryTLSConfigured(cfg *config.Config) bool {
	switch strings.ToLower(strings.TrimSpace(cfg.TLS.Mode)) {
	case "autocert":
		return strings.TrimSpace(cfg.Server.Hostname) != ""
	case "manual":
		return strings.TrimSpace(cfg.TLS.CertFile) != "" && strings.TrimSpace(cfg.TLS.KeyFile) != ""
	default:
		return false
	}
}

func (s *Server) discoveryDomain() string {
	if domain := strings.TrimSpace(s.cfg.Server.Domain); domain != "" {
		return strings.ToLower(domain)
	}
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s.cfg.Server.Hostname), "mail."))
}

func (s *Server) discoveryEmailDomain(value string) (string, bool) {
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value {
		return "", false
	}
	_, domain, found := strings.Cut(address.Address, "@")
	if !found || domain == "" {
		return "", false
	}
	domain = strings.ToLower(domain)
	if strings.EqualFold(domain, s.discoveryDomain()) {
		return domain, true
	}
	if s.db != nil {
		if configured, err := s.db.GetDomainByName(domain); err == nil && configured != nil {
			return domain, true
		}
	}
	return "", false
}

func listenerPort(address string, fallback int) int {
	if index := strings.LastIndex(address, ":"); index >= 0 {
		if port, err := strconv.Atoi(address[index+1:]); err == nil && port > 0 && port <= 65535 {
			return port
		}
	}
	return fallback
}

func writeDiscoveryXML(w http.ResponseWriter, value any) {
	payload, err := xml.Marshal(value)
	if err != nil {
		http.Error(w, "discovery unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append([]byte(xml.Header), payload...))
}
