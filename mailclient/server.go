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

// Server owns the optional POP3-over-TLS and SMTP submission listeners.
type Server struct {
	cfg       *config.Config
	db        *store.DB
	queue     *delivery.Queue
	tlsConfig *tls.Config

	mu        sync.Mutex
	listeners []net.Listener
	quit      chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
	sem       chan struct{}
	maildrops sync.Map
	authMu    sync.Mutex
	auth      map[string]authWindow
}

type authWindow struct {
	started time.Time
	count   int
}

func NewServer(cfg *config.Config, db *store.DB, queue *delivery.Queue, tlsConfig *tls.Config) *Server {
	return &Server{cfg: cfg, db: db, queue: queue, tlsConfig: tlsConfig, quit: make(chan struct{}), sem: make(chan struct{}, cfg.Clients.MaxConnections), auth: make(map[string]authWindow)}
}

func (s *Server) Start() error {
	if !s.cfg.Clients.Enabled {
		logging.Info("[mail-clients] POP3 and submission are disabled")
		return nil
	}
	if s.tlsConfig == nil || (len(s.tlsConfig.Certificates) == 0 && s.tlsConfig.GetCertificate == nil) {
		return fmt.Errorf("mail clients enabled but no TLS certificate is available")
	}
	if s.cfg.Clients.POP3.IsEnabled(true) {
		listener, err := tls.Listen("tcp", s.cfg.Clients.POP3.ListenAddr, s.tlsConfig.Clone())
		if err != nil {
			s.closeListeners()
			return fmt.Errorf("POP3 TLS listen on %s: %w", s.cfg.Clients.POP3.ListenAddr, err)
		}
		s.addListener(listener)
		s.wg.Add(1)
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
		s.wg.Add(1)
		go s.acceptLoop(listener, "submission", s.handleSubmission)
		logging.Info(fmt.Sprintf("[mail-clients] authenticated SMTP submission listening on %s (STARTTLS required)", s.cfg.Clients.Submission.ListenAddr))
	}
	return nil
}

func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		close(s.quit)
		s.closeListeners()
		s.wg.Wait()
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
	defer s.wg.Done()
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
		case s.sem <- struct{}{}:
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
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

func (s *Server) allowAuthentication(remoteAddress string) bool {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = remoteAddress
	}
	now := time.Now()
	s.authMu.Lock()
	defer s.authMu.Unlock()
	window := s.auth[host]
	if window.started.IsZero() || now.Sub(window.started) >= time.Minute {
		window = authWindow{started: now}
	}
	if window.count >= s.cfg.Clients.AuthAttempts {
		return false
	}
	window.count++
	s.auth[host] = window
	return true
}
