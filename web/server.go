package web

import (
	"log"
	"net/http"
	"time"

	backupops "gomail/backup"
	"gomail/config"
	"gomail/delivery"
	"gomail/mta_sts"
	"gomail/reporting"
	"gomail/security"
	"gomail/store"
	"gomail/templates"
	"gomail/web/handlers"

	"golang.org/x/crypto/acme/autocert"
)

// Server is the HTTP/HTTPS web server for the mail interface.
type Server struct {
	cfg              *config.Config
	db               *store.DB
	queue            *delivery.Queue
	sessionMgr       *security.SessionManager
	loginRateLimiter *LoginRateLimiter
	httpServer       *http.Server
	enqueueFunc      reporting.EnqueueFunc
	backupManager    *backupops.Manager
}

// NewServer creates the web server with all routes.
func NewServer(cfg *config.Config, db *store.DB, queue *delivery.Queue, enqueueFunc reporting.EnqueueFunc, backupManagers ...*backupops.Manager) *Server {
	tlsEnabled := cfg.Web.IsTLSEnabled()
	secureRequest := tlsEnabled || cfg.Web.ExternalHTTPS
	sessionMgr := security.NewSessionManager(db, cfg.Web.SessionMaxAge, cfg.Security.CSRFKey, secureRequest)
	loginRateLimiter := NewLoginRateLimiter()
	var backupManager *backupops.Manager
	if len(backupManagers) > 0 {
		backupManager = backupManagers[0]
	}

	s := &Server{
		cfg:              cfg,
		db:               db,
		queue:            queue,
		sessionMgr:       sessionMgr,
		loginRateLimiter: loginRateLimiter,
		enqueueFunc:      enqueueFunc,
		backupManager:    backupManager,
	}

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	// Wrap with security headers (HSTS only when TLS is enabled)
	handler := security.SecureHeaders(mux, secureRequest)
	// Wrap with rate limiter (configurable, applies only to non-static requests)
	rateLimitPerMin := cfg.Web.GetRateLimitPerMin()
	log.Printf("[web] rate limiter: %d requests/minute per IP (static assets exempt)", rateLimitPerMin)
	rateLimiter := NewWebRateLimiter(rateLimitPerMin)
	handler = rateLimiter.Middleware(handler)
	// Resolve and validate the client IP before any limiter reads forwarding headers.
	handler = TrustedProxyMiddleware(cfg.Web.TrustedProxies, handler)
	// ParseMultipartForm's argument is a memory threshold, not an upload cap.
	// Bound every request body before form parsing can spill arbitrarily to disk.
	maxBodyBytes := cfg.SMTP.MaxMessageSize
	if maxBodyBytes <= 0 {
		maxBodyBytes = 25 << 20
	}
	if maxBodyBytes > 1<<30 {
		maxBodyBytes = 1 << 30
	}
	maxBodyBytes = maxBodyBytes*2 + 1<<20
	inner := handler
	handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		inner.ServeHTTP(w, r)
	})

	// When TLS is enabled, listen on HTTPS port; otherwise HTTP port
	addr := cfg.Web.ListenAddr
	if !tlsEnabled {
		addr = cfg.Web.HTTPAddr
		if addr == "" {
			addr = ":80"
		}
	}

	s.httpServer = &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       60 * time.Second,
		Handler:           handler,
	}

	return s
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	// Static files (from embedded filesystem)
	mux.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		templates.ServeStatic(w, r)
	})

	// MTA-STS well-known endpoint
	policy := mta_sts.DefaultPolicy(s.cfg.Server.Hostname)
	mux.HandleFunc("/.well-known/mta-sts.txt", handlers.MTASTSHandler(policy))
	mux.HandleFunc("/.well-known/autoconfig/mail/config-v1.1.xml", s.thunderbirdAutoconfig)
	mux.HandleFunc("/mail/config-v1.1.xml", s.thunderbirdAutoconfig)
	mux.HandleFunc("/autodiscover/autodiscover.xml", s.autodiscover)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.db.PingContext(r.Context()); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		if status, err := s.db.DiskPressureStatus(); err != nil || status.RefusingWrites {
			http.Error(w, "insufficient system storage", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ready\n"))
	})

	// ACME challenge endpoint (let autocert handler deal with it)
	// This must NOT require authentication so Let's Encrypt can validate
	mux.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, r *http.Request) {
		// The autocert.Manager.HTTPHandler wrapper handles actual challenges
		// If we get here without a valid challenge, return 404
		log.Printf("[web] ACME fallback route hit: %s (no active challenge)", r.RequestURI)
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("No ACME challenge at this path"))
	})

	// Auth routes (no session required)
	authHandler := handlers.NewAuthHandler(s.db, s.sessionMgr)
	authHandler.SetLoginRateLimiter(s.loginRateLimiter)
	mux.HandleFunc("/login", authHandler.LoginPage)
	mux.Handle("/logout", s.sessionMgr.RequireAuth(http.HandlerFunc(authHandler.Logout)))

	// Protected routes
	inboxHandler := handlers.NewInboxHandler(s.db, s.sessionMgr, s.cfg.Security.CSRFKey+s.cfg.Web.SessionSecret)
	messageHandler := handlers.NewMessageHandler(s.cfg, s.db, s.queue, s.sessionMgr)
	composeHandler := handlers.NewComposeHandler(s.cfg, s.db, s.queue, s.sessionMgr)
	forwardHandler := handlers.NewForwardHandler(s.cfg, s.db, s.queue, s.sessionMgr)
	settingsHandler := handlers.NewSettingsHandler(s.db, s.sessionMgr)

	mux.Handle("/", s.sessionMgr.RequireAuth(http.HandlerFunc(inboxHandler.Welcome)))
	mux.Handle("/inbox", s.sessionMgr.RequireAuth(http.HandlerFunc(inboxHandler.Inbox)))
	mux.Handle("/starred", s.sessionMgr.RequireAuth(http.HandlerFunc(inboxHandler.Starred)))
	mux.Handle("/search", s.sessionMgr.RequireAuth(http.HandlerFunc(inboxHandler.Search)))
	mux.Handle("/api/messages/action", s.sessionMgr.RequireAuth(http.HandlerFunc(messageHandler.BulkAction)))
	mux.Handle("/sent", s.sessionMgr.RequireAuth(http.HandlerFunc(inboxHandler.Sent)))
	mux.Handle("/folder/{folderID}", s.sessionMgr.RequireAuth(http.HandlerFunc(inboxHandler.FolderView)))
	mux.Handle("/message/", s.sessionMgr.RequireAuth(http.HandlerFunc(messageHandler.View)))
	mux.Handle("/message-content/", s.sessionMgr.RequireAuth(http.HandlerFunc(messageHandler.Content)))
	mux.Handle("/message/delete/", s.sessionMgr.RequireAuth(http.HandlerFunc(messageHandler.Delete)))
	mux.Handle("/message/permanent-delete/", s.sessionMgr.RequireAuth(http.HandlerFunc(messageHandler.PermanentDelete)))
	mux.Handle("/message/star/", s.sessionMgr.RequireAuth(http.HandlerFunc(messageHandler.ToggleStar)))
	mux.Handle("/forward/", s.sessionMgr.RequireAuth(http.HandlerFunc(forwardHandler.ForwardPage)))
	mux.Handle("/forward-send", s.sessionMgr.RequireAuth(http.HandlerFunc(forwardHandler.Send)))
	mux.Handle("/compose", s.sessionMgr.RequireAuth(http.HandlerFunc(composeHandler.ComposePage)))
	mux.Handle("/send", s.sessionMgr.RequireAuth(http.HandlerFunc(composeHandler.Send)))
	mux.Handle("/api/drafts", s.sessionMgr.RequireAuth(http.HandlerFunc(composeHandler.SaveDraft)))
	mux.Handle("/draft/delete/", s.sessionMgr.RequireAuth(http.HandlerFunc(composeHandler.DeleteDraft)))
	mux.Handle("/attachment/", s.sessionMgr.RequireAuth(http.HandlerFunc(messageHandler.DownloadAttachment)))
	mux.Handle("/settings", s.sessionMgr.RequireAuth(http.HandlerFunc(settingsHandler.Settings)))

	// API endpoints for JS
	mux.Handle("/api/mark-read/", s.sessionMgr.RequireAuth(http.HandlerFunc(messageHandler.MarkRead)))
	mux.Handle("/api/send-mdn/", s.sessionMgr.RequireAuth(http.HandlerFunc(messageHandler.SendMDN)))
	mux.Handle("/api/unread-count", s.sessionMgr.RequireAuth(http.HandlerFunc(inboxHandler.UnreadCount)))

	// Admin panel (requires admin role)
	adminHandler := handlers.NewAdminHandler(s.cfg, s.db, s.sessionMgr, s.enqueueFunc, s.backupManager)
	mux.Handle("/admin", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.Dashboard)))
	mux.Handle("/admin/domains", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.Domains)))
	mux.Handle("/admin/domain/edit/", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.DomainEdit)))
	mux.Handle("/admin/domain/report-recipient/", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.DomainReportRecipient)))
	mux.Handle("/admin/domain/dkim/", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.DomainGenerateDKIM)))
	mux.Handle("/admin/domain/delete/", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.DomainDelete)))
	mux.Handle("/admin/accounts", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.Accounts)))
	mux.Handle("/admin/aliases", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.Aliases)))
	mux.Handle("/admin/account/edit/", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.AccountEdit)))
	mux.Handle("/admin/account/delete/", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.AccountDelete)))
	mux.Handle("/admin/dmarc-feedback", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.DMARCFeedback)))
	mux.Handle("/admin/dmarc-reports-manual", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.SendDMARCReportsNow)))
	mux.Handle("/admin/tls-rpt", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.TLSRPTReports)))
	mux.Handle("/admin/received-reports", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.ReceivedReports)))
	mux.Handle("/admin/tls-rpt-manual", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.SendTLSRPTReportsNow)))
	mux.Handle("/admin/greylisting", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.GreylistingEntries)))
	mux.Handle("/admin/tarpitting", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.TarpittingEntries)))
	mux.Handle("/admin/verp-bounces", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.VERPBounces)))
	mux.Handle("/admin/backups", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.Backups)))
	mux.Handle("/admin/configuration", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.Configuration)))
	mux.Handle("/admin/smtp-auth", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.SMTPAuth)))
	mux.Handle("/admin/outbound-limits", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.OutboundLimits)))
	mux.Handle("/admin/queue", s.sessionMgr.RequireAdmin(http.HandlerFunc(adminHandler.OutboundQueue)))
}

// GetHTTPServer returns the underlying http.Server for TLS configuration.
func (s *Server) GetHTTPServer() *http.Server {
	return s.httpServer
}

// IntegrateAutocert wraps the HTTP server handler with ACME challenge support.
// Used when running behind a reverse proxy (nginx handles port 80, proxies to GoMail).
func (s *Server) IntegrateAutocert(autocertMgr *autocert.Manager) {
	log.Printf("[web] autocert wrapper integrated - /.well-known/acme-challenge/ will be intercepted")
	s.httpServer.Handler = autocertMgr.HTTPHandler(s.httpServer.Handler)
}

// ListenAndServeTLS starts the HTTPS server with the given TLS config.
func (s *Server) ListenAndServeTLS(certFile, keyFile string) error {
	log.Printf("[web] HTTPS server listening on %s", s.httpServer.Addr)
	return s.httpServer.ListenAndServeTLS(certFile, keyFile)
}

// ListenAndServe starts a plain HTTP server (no TLS).
func (s *Server) ListenAndServe() error {
	log.Printf("[web] HTTP server listening on %s (TLS disabled)", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown() error {
	return s.httpServer.Close()
}
