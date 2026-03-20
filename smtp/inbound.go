package smtp

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"gomail/auth"
	"gomail/config"
	"gomail/parser"
	"gomail/store"
)

// InboundServer listens for incoming SMTP connections.
type InboundServer struct {
	cfg         *config.Config
	db          *store.DB
	tlsConfig   *tls.Config
	rateLimiter *RateLimiter
	listener    net.Listener
	wg          sync.WaitGroup
	quit        chan struct{}
}

// NewInboundServer creates a new inbound SMTP server.
func NewInboundServer(cfg *config.Config, db *store.DB, tlsCfg *tls.Config) *InboundServer {
	return &InboundServer{
		cfg:       cfg,
		db:        db,
		tlsConfig: tlsCfg,
		rateLimiter: NewRateLimiter(
			cfg.SMTP.RateLimit.ConnectionsPerMinute,
			cfg.SMTP.RateLimit.MessagesPerMinute,
		),
		quit: make(chan struct{}),
	}
}

// Start begins listening for SMTP connections.
func (s *InboundServer) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", s.cfg.SMTP.ListenAddr)
	if err != nil {
		return fmt.Errorf("SMTP listen on %s: %w", s.cfg.SMTP.ListenAddr, err)
	}

	log.Printf("[smtp] inbound listening on %s", s.cfg.SMTP.ListenAddr)

	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// Stop gracefully shuts down the SMTP server.
func (s *InboundServer) Stop() {
	close(s.quit)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	log.Println("[smtp] inbound server stopped")
}

func (s *InboundServer) acceptLoop() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				log.Printf("[smtp] accept error: %v", err)
				continue
			}
		}

		// Rate limit by IP
		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if !s.rateLimiter.AllowConnection(ip) {
			log.Printf("[smtp] rate limit: rejecting connection from %s", ip)
			conn.Close()
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn)
		}()
	}
}

func (s *InboundServer) handleConnection(conn net.Conn) {
	session := NewSession(
		conn,
		s.cfg.Server.Hostname,
		s.cfg.Server.Domain,
		s.tlsConfig,
		s.cfg.SMTP.MaxMessageSize,
		s.cfg.SMTP.MaxRecipients,
		time.Duration(s.cfg.SMTP.ReadTimeout)*time.Second,
		time.Duration(s.cfg.SMTP.WriteTimeout)*time.Second,
	)

	// Override the DATA handler to intercept the message
	s.runSession(session)
}

// runSession is like Session.Handle() but with our message processing integrated.
func (s *InboundServer) runSession(sess *Session) {
	defer sess.conn.Close()

	sess.send(220, fmt.Sprintf("%s ESMTP GoMail ready", sess.hostname))
	sess.state = StateReady

	for sess.state != StateQuit {
		sess.conn.SetReadDeadline(time.Now().Add(sess.readTimeout))

		line, err := sess.reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(parts[0])

		if cmd == "DATA" {
			if sess.state != StateRcpt || len(sess.rcptTo) == 0 {
				sess.send(503, "Bad sequence of commands")
				continue
			}

			// Rate limit messages
			if !s.rateLimiter.AllowMessage(sess.clientIP) {
				sess.send(451, "Too many messages, try again later")
				continue
			}

			sess.handleDATA()

			// Process the received message
			if sess.data.Len() > 0 {
				if err := s.processMessage(sess); err != nil {
					log.Printf("[smtp] message processing error from %s: %v", sess.clientAddr, err)
					sess.send(451, "Message processing failed, try again later")
				} else {
					sess.send(250, "OK message accepted for delivery")
				}
				sess.reset()
			}
		} else {
			sess.handleCommand(line)
		}
	}
}

// processMessage runs authentication checks, parses, and stores an inbound message.
func (s *InboundServer) processMessage(sess *Session) error {
	rawMessage := sess.GetData()
	mailFrom := sess.GetMailFrom()
	rcptTo := sess.GetRcptTo()
	clientIP := sess.GetClientIP()

	log.Printf("[smtp] processing message from=%s to=%v ip=%s size=%d",
		mailFrom, rcptTo, clientIP, len(rawMessage))

	// --- Authentication checks ---
	authBuilder := auth.NewAuthResultsBuilder(s.cfg.Server.Hostname)

	// SPF
	spfResult, spfDetail := auth.CheckSPF(clientIP, mailFrom)
	authBuilder.AddSPF(spfResult, spfDetail, mailFrom)
	log.Printf("[smtp] SPF: %s (%s)", spfResult, spfDetail)

	// DKIM
	dkimResult, dkimDetail := auth.VerifyDKIM(rawMessage)
	authBuilder.AddDKIM(dkimResult, dkimDetail, "", "")
	log.Printf("[smtp] DKIM: %s (%s)", dkimResult, dkimDetail)

	// DMARC
	parsed, err := parser.Parse(rawMessage)
	if err != nil {
		return fmt.Errorf("parsing message: %w", err)
	}

	fromDomain := extractDomain(parsed.From)
	spfDomain := extractDomain(mailFrom)

	dmarcResult := auth.CheckDMARC(fromDomain, spfResult, spfDomain, dkimResult, "")
	authBuilder.AddDMARC(dmarcResult.Result, dmarcResult.Details, fromDomain)
	log.Printf("[smtp] DMARC: %s (%s)", dmarcResult.Result, dmarcResult.Details)

	authResults := authBuilder.Build()

	// Serialize recipients
	rcptJSON, _ := json.Marshal(rcptTo)

	// Generate message ID if missing
	messageID := parsed.MessageID
	if messageID == "" {
		messageID = fmt.Sprintf("%d.%s@%s", time.Now().UnixNano(), clientIP, s.cfg.Server.Hostname)
	}

	// --- Store the message ---
	msg := &store.Message{
		MessageID:      messageID,
		Direction:      "inbound",
		MailFrom:       mailFrom,
		RcptTo:         string(rcptJSON),
		FromAddr:       parsed.From,
		ToAddr:         parsed.To,
		CcAddr:         parsed.Cc,
		ReplyTo:        parsed.ReplyTo,
		Subject:        parsed.Subject,
		TextBody:       parsed.TextBody,
		HTMLBody:       parsed.HTMLBody,
		RawHeaders:     parsed.RawHeaders,
		RawMessage:     rawMessage,
		Size:           int64(len(rawMessage)),
		HasAttachments: len(parsed.Attachments) > 0,
		SPFResult:      string(spfResult),
		DKIMResult:     dkimResult,
		DMARCResult:    string(dmarcResult.Result),
		AuthResults:    authResults,
		ReceivedAt:     time.Now(),
	}

	msgID, err := s.db.SaveMessage(msg)
	if err != nil {
		return fmt.Errorf("saving message: %w", err)
	}

	// Save attachments
	if len(parsed.Attachments) > 0 {
		records, err := parser.SaveAttachments(parsed.Attachments, msgID, s.db.AttachmentsPath())
		if err != nil {
			log.Printf("[smtp] attachment save error: %v", err)
		} else {
			for _, rec := range records {
				if _, err := s.db.SaveAttachment(rec); err != nil {
					log.Printf("[smtp] attachment db save error: %v", err)
				}
			}
		}
	}

	log.Printf("[smtp] message stored id=%d msgid=%s from=%s subject=%s",
		msgID, messageID, mailFrom, parsed.Subject)

	return nil
}

// extractDomain gets the domain part from an email address or From header.
func extractDomain(addr string) string {
	// Handle "Name <email@domain>" format
	if idx := strings.LastIndex(addr, "<"); idx >= 0 {
		addr = addr[idx+1:]
		if end := strings.Index(addr, ">"); end >= 0 {
			addr = addr[:end]
		}
	}
	parts := strings.SplitN(addr, "@", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return addr
}
