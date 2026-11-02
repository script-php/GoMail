// Package mailclient provides opt-in protocols for desktop and mobile clients.
package mailclient

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"gomail/config"
	"gomail/delivery"
	"gomail/logging"
	"gomail/store"
)

// Server owns the optional IMAP/POP3-over-TLS and SMTP submission listeners.
type Server struct {
	cfg       *config.Config
	db        *store.DB
	queue     *delivery.Queue
	tlsConfig *tls.Config

	mu          sync.Mutex
	listeners   []net.Listener
	quit        chan struct{}
	stopOnce    sync.Once
	acceptWG    sync.WaitGroup
	wg          sync.WaitGroup
	sem         chan struct{}
	connections map[net.Conn]struct{}
	maildrops   sync.Map
	authMu      sync.Mutex
	auth        map[string]authWindow
	authCleaned time.Time
}

type authWindow struct {
	started time.Time
	count   int
}

func NewServer(cfg *config.Config, db *store.DB, queue *delivery.Queue, tlsConfig *tls.Config) *Server {
	return &Server{cfg: cfg, db: db, queue: queue, tlsConfig: tlsConfig, quit: make(chan struct{}), sem: make(chan struct{}, cfg.Clients.MaxConnections), connections: make(map[net.Conn]struct{}), auth: make(map[string]authWindow)}
}

func (s *Server) Start() error {
	if !s.cfg.Clients.Enabled {
		logging.Info("[mail-clients] IMAP, POP3 and submission are disabled")
		return nil
	}
	if s.tlsConfig == nil || (len(s.tlsConfig.Certificates) == 0 && s.tlsConfig.GetCertificate == nil) {
		return fmt.Errorf("mail clients enabled but no TLS certificate is available")
	}
	if s.cfg.Clients.IMAP.IsEnabled(true) {
		listener, err := tls.Listen("tcp", s.cfg.Clients.IMAP.ListenAddr, s.tlsConfig.Clone())
		if err != nil {
			s.closeListeners()
			return fmt.Errorf("IMAP TLS listen on %s: %w", s.cfg.Clients.IMAP.ListenAddr, err)
		}
		s.addListener(listener)
		s.acceptWG.Add(1)
		go s.acceptLoop(listener, "imap", s.handleIMAP)
		logging.Info(fmt.Sprintf("[mail-clients] IMAP over TLS listening on %s", s.cfg.Clients.IMAP.ListenAddr))
	}
	if s.cfg.Clients.POP3.IsEnabled(true) {
		listener, err := tls.Listen("tcp", s.cfg.Clients.POP3.ListenAddr, s.tlsConfig.Clone())
		if err != nil {
			s.closeListeners()
			return fmt.Errorf("POP3 TLS listen on %s: %w", s.cfg.Clients.POP3.ListenAddr, err)
		}
		s.addListener(listener)
		s.acceptWG.Add(1)
		go s.acceptLoop(listener, "pop3", s.handlePOP3)
		logging.Info(fmt.Sprintf("[mail-clients] POP3 over TLS listening on %s", s.cfg.Clients.POP3.ListenAddr))
	}
	if s.cfg.Clients.Submission.IsEnabled(true) {
		listener, err := net.Listen("tcp", s.cfg.Clients.Submission.ListenAddr)
		if err != nil {
			s.closeListeners()
			return fmt.Errorf("submission listen on %s: %w", s.cfg.Clients.Submission.ListenAddr, err)
		}
		s.addListener(listener)
		s.acceptWG.Add(1)
		go s.acceptLoop(listener, "submission", s.handleSubmission)
		logging.Info(fmt.Sprintf("[mail-clients] authenticated SMTP submission listening on %s (STARTTLS required)", s.cfg.Clients.Submission.ListenAddr))
	}
	return nil
}

func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		close(s.quit)
		s.closeListeners()
		s.acceptWG.Wait()
		done := make(chan struct{})
		go func() { s.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			s.mu.Lock()
			for conn := range s.connections {
				_ = conn.Close()
			}
			s.mu.Unlock()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				logging.Warn("[mail-clients] shutdown deadline exceeded with active sessions")
			}
		}
	})
}

func (s *Server) addListener(listener net.Listener) {
	s.mu.Lock()
	s.listeners = append(s.listeners, listener)
	s.mu.Unlock()
}

func (s *Server) closeListeners() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, listener := range s.listeners {
		_ = listener.Close()
	}
	s.listeners = nil
}

func (s *Server) acceptLoop(listener net.Listener, name string, handler func(net.Conn)) {
	defer s.acceptWG.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				logging.Warn(fmt.Sprintf("[mail-clients] %s accept error: %v", name, err))
				continue
			}
		}
		select {
		case <-s.quit:
			_ = conn.Close()
			return
		default:
		}
		select {
		case s.sem <- struct{}{}:
			s.mu.Lock()
			s.connections[conn] = struct{}{}
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer func() {
					s.mu.Lock()
					delete(s.connections, conn)
					s.mu.Unlock()
				}()
				defer func() { <-s.sem }()
				handler(conn)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func (s *Server) readTimeout() time.Duration {
	return time.Duration(s.cfg.Clients.ReadTimeout) * time.Second
}
func (s *Server) writeTimeout() time.Duration {
	return time.Duration(s.cfg.Clients.WriteTimeout) * time.Second
}

func (s *Server) accountStillActive(account *store.Account) bool {
	if account == nil || s.db == nil {
		return false
	}
	current, err := s.db.GetAccountByEmail(account.Email)
	return err == nil && current != nil && current.ID == account.ID
}

func (s *Server) allowAuthentication(remoteAddress string) bool {
	host := authenticationHost(remoteAddress)
	now := time.Now()
	s.authMu.Lock()
	defer s.authMu.Unlock()
	s.cleanupAuthentication(now)
	window := s.auth[host]
	if window.started.IsZero() || now.Sub(window.started) >= time.Minute {
		return true
	}
	return window.count < s.cfg.Clients.AuthAttempts
}

const maxAuthenticationHosts = 8192

func authenticationHost(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return remoteAddress
	}
	return host
}

func (s *Server) recordAuthenticationFailure(remoteAddress string) {
	host := authenticationHost(remoteAddress)
	now := time.Now()
	s.authMu.Lock()
	defer s.authMu.Unlock()
	s.cleanupAuthentication(now)
	window := s.auth[host]
	if window.started.IsZero() || now.Sub(window.started) >= time.Minute {
		window = authWindow{started: now}
	}
	if _, exists := s.auth[host]; !exists && len(s.auth) >= maxAuthenticationHosts {
		var oldestHost string
		var oldestTime time.Time
		for key, entry := range s.auth {
			if oldestHost == "" || entry.started.Before(oldestTime) {
				oldestHost, oldestTime = key, entry.started
			}
		}
		delete(s.auth, oldestHost)
	}
	window.count++
	s.auth[host] = window
}

func (s *Server) cleanupAuthentication(now time.Time) {
	if !s.authCleaned.IsZero() && now.Sub(s.authCleaned) < time.Minute {
		return
	}
	for host, window := range s.auth {
		if now.Sub(window.started) >= time.Minute {
			delete(s.auth, host)
		}
	}
	s.authCleaned = now
}
