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
	// Get current list of accepted domains from DB
	domains, err := s.db.ListAllDomainNames()
	if err != nil {
		log.Printf("[smtp] error loading domains: %v", err)
		conn.Close()
		return
	}

	accountExists := func(email string) bool {
		acct, err := s.db.GetAccountByEmail(email)
		return err == nil && acct != nil && acct.IsActive
	}

	session := NewSession(
		conn,
		s.cfg.Server.Hostname,
		domains,
		accountExists,
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

	// --- Add Received header ---
	receivedHeader := fmt.Sprintf("Received: from %s\r\n\tby %s\r\n\twith SMTP%s\r\n\tid %s\r\n\tfor <%s>;\r\n\t%s\r\n",
		clientIP,
		s.cfg.Server.Hostname,
		func() string {
			if sess.tls {
				return "S"
			}
			return ""
		}(),
		fmt.Sprintf("%d.%s@%s", time.Now().UnixNano(), clientIP, s.cfg.Server.Hostname),
		strings.Join(rcptTo, ">, <"),
		time.Now().Format(time.RFC1123Z),
	)
	rawMessage = append([]byte(receivedHeader), rawMessage...)

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

	// Prepend Authentication-Results header to raw message so clients can see it
	authResultsHeader := authResults + "\r\n"
	rawMessage = append([]byte(authResultsHeader), rawMessage...)

	// --- Validate ARC Chain (if present) ---
	arcValidation := auth.ValidateARCChain(rawMessage)
	switch arcValidation.Status {
	case "pass":
		log.Printf("[smtp] ARC ✓ PASS: valid chain through instance=%d",
			arcValidation.HighestValid)
	case "fail":
		log.Printf("[smtp] ARC ✗ FAIL: %s", arcValidation.Details)
	case "permerror":
		log.Printf("[smtp] ARC ⚠ PERMERROR: permanent error - %s", arcValidation.Details)
	case "temperror":
		log.Printf("[smtp] ARC ⏱ TEMPERROR: temporary error - %s", arcValidation.Details)
	case "none":
		log.Printf("[smtp] ARC - NONE: no ARC headers (original email)")
	default:
		log.Printf("[smtp] ARC ? UNKNOWN: status=%s", arcValidation.Status)
	}

	// Determine if this email should be quarantined due to ARC failure
	arcFailed := arcValidation.Status == "fail" || arcValidation.Status == "permerror"
	if arcFailed {
		log.Printf("[smtp] ARC validation failed - will quarantine to spam: %s", arcValidation.Details)
	}

	// NOTE: Do NOT add ARC headers for inbound original emails.
	// ARC headers are only added when FORWARDING/RELAYING messages.
	// For original emails with no prior ARC chain, store without modification.

	// --- Check for MDN request ---
	mdnRequested := parsed.MDNRequestedBy != ""
	mdnAddress := parsed.MDNRequestedBy
	if mdnRequested {
		log.Printf("[smtp] MDN requested for %s to %s", parsed.MessageID, mdnAddress)
	}

	// --- Store the message for each recipient's account ---
	rcptJSON, _ := json.Marshal(rcptTo)

	messageID := parsed.MessageID
	if messageID == "" {
		messageID = fmt.Sprintf("%d.%s@%s", time.Now().UnixNano(), clientIP, s.cfg.Server.Hostname)
	}

	// Deliver to each recipient
	for _, rcpt := range rcptTo {
		// Note: DMARC enforcement is now done per-recipient via folder assignment below
		// p=reject and p=quarantine both result in messages going to spam folder
		// p=none messages go to inbox normally

		// Check if DMARC failed for this domain
		if dmarcResult.Result == "fail" {
			switch dmarcResult.Policy {
			case "reject":
				log.Printf("[smtp] DMARC p=reject: accepting but quarantining mail from %s (auth check failed)", fromDomain)
			case "quarantine":
				log.Printf("[smtp] DMARC p=quarantine: accepting but marking suspicious from %s", fromDomain)
			case "none":
				log.Printf("[smtp] DMARC p=none: accepting in observation mode from %s", fromDomain)
			}
		}

		// Look up the account for this recipient
		account, err := s.db.GetAccountByEmail(rcpt)
		if err != nil {
			log.Printf("[smtp] account lookup error for %s: %v", rcpt, err)
			continue
		}
		if account == nil || !account.IsActive {
			log.Printf("[smtp] no active account for %s, skipping", rcpt)
			continue
		}

		accountID := account.ID

		// Determine folder based on auth results
		var folderID *int64

		// Route to inbox ONLY if all three authentications pass
		allAuthPass := spfResult == "pass" && dkimResult == "pass" && dmarcResult.Result == "pass"
		authFailed := arcFailed || !allAuthPass

		if authFailed {
			// Any auth failure → spam folder
			if arcFailed {
				log.Printf("[smtp] ARC failed: quarantining to spam (reason: %s)", arcValidation.Details)
			} else {
				log.Printf("[smtp] auth check failed - SPF: %s, DKIM: %s, DMARC: %s - quarantining to spam",
					spfResult, dkimResult, dmarcResult.Result)
			}
			spamFolder, err := s.db.GetFolderByType(accountID, "spam")
			if err != nil {
				log.Printf("[smtp] error getting spam folder: %v", err)
			} else if spamFolder != nil {
				folderID = &spamFolder.ID
				log.Printf("[smtp] message routed to spam folder=%d", spamFolder.ID)
			} else {
				log.Printf("[smtp] warning: spam folder not found for account %d, using NULL", accountID)
			}
		} else {
			// All auth passed - route to inbox
			inboxFolder, err := s.db.GetFolderByType(accountID, "inbox")
			if err != nil {
				log.Printf("[smtp] error getting inbox folder for account %d: %v", accountID, err)
			} else if inboxFolder != nil {
				folderID = &inboxFolder.ID
				log.Printf("[smtp] all auth passed (SPF: %s, DKIM: %s, DMARC: %s) - assigning to inbox folder=%d",
					spfResult, dkimResult, dmarcResult.Result, inboxFolder.ID)
			} else {
				log.Printf("[smtp] warning: inbox folder not found for account %d, using NULL", accountID)
			}
		}

		msg := &store.Message{
			AccountID:      accountID,
			FolderID:       folderID,
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
			AuthResults:    authResults + "\nARC-Validation: " + arcValidation.Status,
			MDNRequested:   mdnRequested,
			MDNAddress:     mdnAddress,
			ReceivedAt:     time.Now(),
		}

		// Log what folder_id will be saved
		if folderID != nil {
			log.Printf("[smtp] saving message subject=%q with folder_id=%d (rcpt=%s)", parsed.Subject, *folderID, rcpt)
		} else {
			log.Printf("[smtp] saving message subject=%q with folder_id=NULL (rcpt=%s)", parsed.Subject, rcpt)
		}

		msgID, err := s.db.SaveMessage(msg)
		if err != nil {
			log.Printf("[smtp] saving message for %s: %v", rcpt, err)
			continue
		}

		// Update folder counts
		if folderID != nil {
			s.db.UpdateFolderCounts(*folderID)
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

		log.Printf("[smtp] message stored id=%d account=%d msgid=%s from=%s to=%s subject=%s",
			msgID, accountID, messageID, mailFrom, rcpt, parsed.Subject)
	}

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
