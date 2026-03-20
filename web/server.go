package web

import (
	"log"
	"net/http"

	"gomail/config"
	"gomail/delivery"
	"gomail/mta_sts"
	"gomail/security"
	"gomail/store"
	"gomail/web/handlers"
)

// Server is the HTTP/HTTPS web server for the mail interface.
type Server struct {
	cfg            *config.Config
	db             *store.DB
	queue          *delivery.Queue
	sessionMgr     *security.SessionManager
	httpServer     *http.Server
}

// NewServer creates the web server with all routes.
func NewServer(cfg *config.Config, db *store.DB, queue *delivery.Queue) *Server {
	sessionMgr := security.NewSessionManager(db, cfg.Web.SessionMaxAge, cfg.Security.CSRFKey)

	s := &Server{
		cfg:        cfg,
		db:         db,
		queue:      queue,
		sessionMgr: sessionMgr,
	}

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	// Wrap with security headers
	handler := security.SecureHeaders(mux)

	s.httpServer = &http.Server{
		Addr:    cfg.Web.ListenAddr,
		Handler: handler,
	}

	return s
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	// Static files
	fs := http.FileServer(http.Dir("web/static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// MTA-STS well-known endpoint
	policy := mta_sts.DefaultPolicy(s.cfg.Server.Hostname)
	mux.HandleFunc("/.well-known/mta-sts.txt", handlers.MTASTSHandler(policy))

	// Auth routes (no session required)
	authHandler := handlers.NewAuthHandler(s.cfg, s.db, s.sessionMgr)
	mux.HandleFunc("/login", authHandler.LoginPage)
	mux.HandleFunc("/logout", authHandler.Logout)

	// Protected routes
	inboxHandler := handlers.NewInboxHandler(s.db, s.sessionMgr)
	messageHandler := handlers.NewMessageHandler(s.db, s.sessionMgr)
	composeHandler := handlers.NewComposeHandler(s.cfg, s.db, s.queue, s.sessionMgr)

	mux.Handle("/", s.sessionMgr.RequireAuth(http.HandlerFunc(inboxHandler.Inbox)))
	mux.Handle("/inbox", s.sessionMgr.RequireAuth(http.HandlerFunc(inboxHandler.Inbox)))
	mux.Handle("/sent", s.sessionMgr.RequireAuth(http.HandlerFunc(inboxHandler.Sent)))
	mux.Handle("/message/", s.sessionMgr.RequireAuth(http.HandlerFunc(messageHandler.View)))
	mux.Handle("/message/delete/", s.sessionMgr.RequireAuth(http.HandlerFunc(messageHandler.Delete)))
	mux.Handle("/message/star/", s.sessionMgr.RequireAuth(http.HandlerFunc(messageHandler.ToggleStar)))
	mux.Handle("/compose", s.sessionMgr.RequireAuth(http.HandlerFunc(composeHandler.ComposePage)))
	mux.Handle("/send", s.sessionMgr.RequireAuth(http.HandlerFunc(composeHandler.Send)))
	mux.Handle("/attachment/", s.sessionMgr.RequireAuth(http.HandlerFunc(messageHandler.DownloadAttachment)))

	// API endpoints for JS
	mux.Handle("/api/mark-read/", s.sessionMgr.RequireAuth(http.HandlerFunc(messageHandler.MarkRead)))
	mux.Handle("/api/unread-count", s.sessionMgr.RequireAuth(http.HandlerFunc(inboxHandler.UnreadCount)))
}

// GetHTTPServer returns the underlying http.Server for TLS configuration.
func (s *Server) GetHTTPServer() *http.Server {
	return s.httpServer
}

// ListenAndServeTLS starts the HTTPS server with the given TLS config.
func (s *Server) ListenAndServeTLS(certFile, keyFile string) error {
	log.Printf("[web] HTTPS server listening on %s", s.cfg.Web.ListenAddr)
	return s.httpServer.ListenAndServeTLS(certFile, keyFile)
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown() error {
	return s.httpServer.Close()
}
