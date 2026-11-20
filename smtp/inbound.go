package smtp

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"sync"
	"time"

	"gomail/auth"
	"gomail/config"
	"gomail/dns"
	"gomail/logging"
	"gomail/metrics"
	"gomail/parser"
	"gomail/reporting"
	"gomail/security"
	"gomail/store"
)

// InboundServer listens for incoming SMTP connections.
type InboundServer struct {
	cfg           *config.Config
	db            *store.DB
	tlsConfig     *tls.Config
	rateLimiter   *RateLimiter
	listener      net.Listener
	acceptWG      sync.WaitGroup
	wg            sync.WaitGroup
	stopOnce      sync.Once
	connMu        sync.Mutex
	connections   map[net.Conn]struct{}
	quit          chan struct{}
	connSemaphore chan struct{} // Limits concurrent connections
}

var errInvalidAuthor = errors.New("invalid RFC 5322 From field")
var errInvalidMessage = errors.New("invalid RFC 5322 message")

// authorDomain extracts the one unambiguous domain DMARC is allowed to use.
func authorDomain(headers mail.Header) (string, error) {
	fields := headers["From"]
	if len(fields) != 1 {
		return "", errInvalidAuthor
	}
	authors, err := mail.ParseAddressList(fields[0])
	if err != nil || len(authors) == 0 {
		return "", errInvalidAuthor
	}
	if len(authors) > 1 {
		senders := headers["Sender"]
		if len(senders) != 1 {
			return "", errInvalidAuthor
		}
		if _, err := mail.ParseAddress(senders[0]); err != nil {
			return "", errInvalidAuthor
		}
	}
	var domain string
	for _, author := range authors {
		at := strings.LastIndexByte(author.Address, '@')
		if at < 0 || at == len(author.Address)-1 {
			return "", errInvalidAuthor
		}
		current := strings.ToLower(author.Address[at+1:])
		if domain != "" && domain != current {
			return "", errInvalidAuthor
		}
		domain = current
	}
	return domain, nil
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
		quit:          make(chan struct{}),
		connections:   make(map[net.Conn]struct{}),
		connSemaphore: make(chan struct{}, cfg.SMTP.MaxConnections),
	}
}

// Start begins listening for SMTP connections.
func (s *InboundServer) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", s.cfg.SMTP.ListenAddr)
	if err != nil {
		return fmt.Errorf("SMTP listen on %s: %w", s.cfg.SMTP.ListenAddr, err)
	}

	logging.Info(fmt.Sprintf("[smtp] inbound listening on %s", s.cfg.SMTP.ListenAddr))

	s.acceptWG.Add(1)
	go s.acceptLoop()
	return nil
}

// Stop gracefully shuts down the SMTP server.
func (s *InboundServer) Stop() {
	s.stopOnce.Do(func() {
		close(s.quit)
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.acceptWG.Wait()
		done := make(chan struct{})
		go func() { s.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			s.connMu.Lock()
			for conn := range s.connections {
				_ = conn.Close()
			}
			s.connMu.Unlock()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				logging.Warn("[smtp] shutdown deadline exceeded with active sessions")
			}
		}
		logging.Info("[smtp] inbound server stopped")
	})
}

func (s *InboundServer) acceptLoop() {
	defer s.acceptWG.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				logging.Error(fmt.Sprintf("[smtp] accept error: %v", err))
				continue
			}
		}
		select {
		case <-s.quit:
			_ = conn.Close()
			return
		default:
		}

		// Rate limit by IP
		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if !s.rateLimiter.AllowConnection(ip) {
			logging.Warn(fmt.Sprintf("[smtp] rate limit: rejecting connection from %s", ip))
			rejectInboundConnection(conn, s.cfg.Server.Hostname)
			continue
		}

		// Try to acquire connection slot
		select {
		case s.connSemaphore <- struct{}{}:
			// Slot acquired, handle the connection
			s.connMu.Lock()
			s.connections[conn] = struct{}{}
			s.connMu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer func() {
					s.connMu.Lock()
					delete(s.connections, conn)
					s.connMu.Unlock()
				}()
				defer func() { <-s.connSemaphore }() // Release slot when done
				s.handleConnection(conn)
			}()
		default:
			// No slots available, reject connection
			logging.Warn(fmt.Sprintf("[smtp] max connections reached: rejecting connection from %s", ip))
			rejectInboundConnection(conn, s.cfg.Server.Hostname)
		}
	}
}

// Give clients an explicit temporary failure at connection opening. Keep the
// write bounded so a peer that never reads cannot stall the accept loop.
func rejectInboundConnection(conn net.Conn, hostname string) {
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	_, _ = fmt.Fprintf(conn, "421 %s Service temporarily unavailable, try again later\r\n", hostname)
}

func (s *InboundServer) handleConnection(conn net.Conn) {
	// Get current list of accepted domains from DB
	domains, err := s.db.ListAllDomainNames()
	if err != nil {
		logging.Error(fmt.Sprintf("[smtp] error loading domains: %v", err))
		rejectInboundConnection(conn, s.cfg.Server.Hostname)
		return
	}

	// Verify reverse DNS (PTR) for the connecting IP
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	ptrHostname, ptrValid, err := dns.VerifyPTR(ip)
	if err != nil {
		logging.Warn(fmt.Sprintf("[smtp] PTR lookup failed for %s: %v", ip, err))
	} else {
		if ptrValid {
			logging.Info(fmt.Sprintf("[smtp] PTR verified for %s: %s", ip, ptrHostname))
		} else {
			logging.Info(fmt.Sprintf("[smtp] PTR hostname %s does not resolve back to %s (forward confirmation failed)", ptrHostname, ip))
		}
	}

	accountExists := func(email string) (bool, error) {
		acct, err := s.db.GetDeliveryAccount(email)
		return acct != nil && acct.IsActive, err
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
		ptrHostname,
		ptrValid,
		s.db,
	)
	session.postmasterDomain = s.cfg.Server.Domain

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

		line, err := security.ReadLineLimited(sess.reader, security.SMTPCommandLineLimit)
		if err != nil {
			return
		}
		line, err = security.ParseCRLFCommandLine(line)
		if err != nil {
			sess.sendEnhanced(500, "5.5.2", "Command requires CRLF framing")
			return
		}

		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(parts[0])

		if cmd == "DATA" {
			if len(parts) > 1 && strings.TrimSpace(parts[1]) != "" {
				sess.sendEnhanced(501, "5.5.2", "DATA does not take arguments")
				continue
			}
			if sess.state != StateRcpt || len(sess.rcptTo) == 0 {
				sess.sendEnhanced(503, "5.5.1", "Bad sequence of commands")
				continue
			}

			// Rate limit messages
			if !s.rateLimiter.AllowMessage(sess.clientIP) {
				metrics.IncSMTP("deferred")
				sess.sendEnhanced(451, "4.5.3", "Too many messages, try again later")
				continue
			}

			sess.handleDATA()

			// A completed empty transfer must receive a final answer too.
			if sess.state == StateReady && sess.data.Len() == 0 {
				metrics.IncSMTP("rejected")
				sess.sendEnhanced(554, "5.6.0", "Empty message is not accepted")
				sess.reset()
			} else if sess.data.Len() > 0 {
				if err := sess.validateMessageEncoding(); err != nil {
					metrics.IncSMTP("rejected")
					sess.sendEnhanced(550, "5.7.1", err.Error())
				} else if err := s.processMessage(sess); err != nil {
					metrics.IncSMTP("deferred")
					logging.Error(fmt.Sprintf("[smtp] message processing error from %s: %v", sess.clientAddr, err))
					s.sendProcessingError(sess, err)
				} else {
					metrics.IncSMTP("accepted")
					sess.sendEnhanced(250, "2.0.0", "OK message accepted for delivery")
				}
				sess.reset()
			}
		} else if cmd == "BDAT" {
			// Handle BDAT (RFC 3030 CHUNKING)
			var arg string
			if len(parts) > 1 {
				arg = parts[1]
			}

			// Rate limit messages on first chunk (StateRcpt)
			if sess.state == StateRcpt && !s.rateLimiter.AllowMessage(sess.clientIP) {
				metrics.IncSMTP("deferred")
				sess.rejectBDATChunkForRateLimit(arg)
				continue
			}

			previousState := sess.state
			sess.handleBDAT(arg)

			// Only a completed LAST chunk transitions an active transaction to
			// Ready. A rejected BDAT in Ready must not get a second reply.
			if previousState != StateReady && sess.state == StateReady && sess.data.Len() == 0 {
				metrics.IncSMTP("rejected")
				sess.sendEnhanced(554, "5.6.0", "Empty message is not accepted")
				sess.reset()
			} else if previousState != StateReady && sess.state == StateReady && sess.data.Len() > 0 {
				if err := sess.validateMessageEncoding(); err != nil {
					metrics.IncSMTP("rejected")
					sess.sendEnhanced(550, "5.7.1", err.Error())
				} else if err := s.processMessage(sess); err != nil {
					metrics.IncSMTP("deferred")
					logging.Error(fmt.Sprintf("[smtp] message processing error from %s: %v", sess.clientAddr, err))
					s.sendProcessingError(sess, err)
				} else {
					metrics.IncSMTP("accepted")
					sess.sendEnhanced(250, "2.0.0", "OK message accepted for delivery")
				}
				sess.reset()
			}
		} else {
			sess.handleCommand(line)
		}
	}
}

func (s *InboundServer) sendProcessingError(sess *Session, err error) {
	if errors.Is(err, store.ErrDiskPressure) {
		sess.sendEnhanced(452, "4.3.1", "Insufficient system storage, try again later")
		return
	}
	if errors.Is(err, store.ErrQuotaExceeded) {
		metrics.IncQuota("inbound")
		sess.sendEnhanced(452, "4.2.2", "Mailbox full, try again later")
		return
	}
	if errors.Is(err, errInvalidAuthor) {
		sess.sendEnhanced(554, "5.6.0", "Invalid or ambiguous From field")
		return
	}
	if errors.Is(err, errInvalidMessage) {
		sess.sendEnhanced(554, "5.6.0", "Invalid message format")
		return
	}
	sess.sendEnhanced(451, "4.3.0", "Message processing failed, try again later")
}

// processMessage runs authentication checks, parses, and stores an inbound message.
func (s *InboundServer) processMessage(sess *Session) error {
	rawMessage := sess.GetData()
	// Verify signatures against the message exactly as received. A sender may
	// have signed an Authentication-Results field; stripping that untrusted
	// field before verification would invalidate an otherwise valid signature.
	dkimResult, dkimDetail, dkimDomain, dkimSelector, verifiedDKIMDomains := auth.VerifyDKIMDetailedWithIdentities(rawMessage)
	arcValidation := auth.ValidateARCChain(rawMessage)
	var err error
	rawMessage, err = RemoveExternalAuthenticationResults(rawMessage)
	if err != nil {
		return fmt.Errorf("%w: removing untrusted authentication results: %v", errInvalidMessage, err)
	}
	mailFrom := sess.GetMailFrom()
	rcptTo := sess.GetRcptTo()
	clientIP := sess.GetClientIP()

	logging.Info(fmt.Sprintf("[smtp] processing message from=%s to=%v ip=%s size=%d",
		mailFrom, rcptTo, clientIP, len(rawMessage)))

	// Log PTR verification result
	if sess.ptrValid {
		logging.Info(fmt.Sprintf("[smtp] PTR verified: %s", sess.ptrHostname))
	} else if sess.ptrHostname != "" {
		logging.Info(fmt.Sprintf("[smtp] PTR unverified: %s (no forward confirmation)", sess.ptrHostname))
	} else {
		logging.Info("[smtp] PTR: no reverse DNS records found")
	}

	// --- Add Received header ---
	receivedHeader := inboundReceivedHeader(s.cfg.Server.Hostname, clientIP, rcptTo, sess.tls, time.Now())
	rawMessage = append([]byte(receivedHeader), rawMessage...)

	// --- Authentication checks ---
	authBuilder := auth.NewAuthResultsBuilder(s.cfg.Server.Hostname)

	// SPF
	spfResult, spfDetail := auth.CheckSPFWithHELO(clientIP, mailFrom, sess.ehlo)
	authBuilder.AddSPF(spfResult, spfDetail, mailFrom, sess.ehlo)
	logging.Info(fmt.Sprintf("[smtp] SPF: %s (%s)", spfResult, spfDetail))

	// DKIM
	authBuilder.AddDKIM(dkimResult, dkimDetail, dkimDomain, dkimSelector)
	logging.Info(fmt.Sprintf("[smtp] DKIM: %s (%s)", dkimResult, dkimDetail))

	// DMARC
	parsed, err := parser.Parse(rawMessage)
	if err != nil {
		return fmt.Errorf("%w: parsing message: %v", errInvalidMessage, err)
	}

	logging.Info(fmt.Sprintf("[smtp] parsed message: text_bytes=%d html_bytes=%d attachments=%d",
		len(parsed.TextBody), len(parsed.HTMLBody), len(parsed.Attachments)))

	fromDomain, err := authorDomain(parsed.Headers)
	if err != nil {
		return err
	}
	spfDomain := spfIdentityDomain(mailFrom, sess.ehlo)

	var otherDKIMDomains []string
	if len(verifiedDKIMDomains) > 1 {
		otherDKIMDomains = verifiedDKIMDomains[1:]
	}
	dmarcResult := auth.CheckDMARC(fromDomain, spfResult, spfDomain, dkimResult, dkimDomain, otherDKIMDomains...)
	authBuilder.AddDMARC(dmarcResult.Result, dmarcResult.Details, fromDomain)
	logging.Info(fmt.Sprintf("[smtp] DMARC: %s (%s)", dmarcResult.Result, dmarcResult.Details))

	authResults := authBuilder.Build()

	// Prepend Authentication-Results header to raw message so clients can see it
	authResultsHeader := "Authentication-Results: " + authResults + "\r\n"
	rawMessage = append([]byte(authResultsHeader), rawMessage...)

	// --- Validate ARC Chain (if present) ---
	switch arcValidation.Status {
	case "pass":
		logging.Info(fmt.Sprintf("[smtp] ARC - PASS: valid chain through instance=%d",
			arcValidation.HighestValid))
	case "fail":
		logging.Warn(fmt.Sprintf("[smtp] ARC - FAIL: %s", arcValidation.Details))
	case "permerror":
		logging.Error(fmt.Sprintf("[smtp] ARC - PERMERROR: permanent error - %s", arcValidation.Details))
	case "temperror":
		logging.Warn(fmt.Sprintf("[smtp] ARC - TEMPERROR: temporary error - %s", arcValidation.Details))
	case "none":
		logging.Info("[smtp] ARC - NONE: no ARC headers (original email)")
	default:
		logging.Info(fmt.Sprintf("[smtp] ARC ? UNKNOWN: status=%s", arcValidation.Status))
	}

	// Determine if this email should be quarantined due to ARC failure
	arcFailed := arcValidation.Status == "fail" || arcValidation.Status == "permerror"
	if arcFailed {
		logging.Warn(fmt.Sprintf("[smtp] ARC validation failed - will quarantine to spam: %s", arcValidation.Details))
	}

	// NOTE: Do NOT add ARC headers for inbound original emails.
	// ARC headers are only added when FORWARDING/RELAYING messages.
	// For original emails with no prior ARC chain, store without modification.
	// Final delivery records the trusted SMTP reverse-path. Do this after
	// authentication so forged sender headers cannot affect validation.
	rawMessage, err = FinalDeliveryReturnPath(rawMessage, mailFrom)
	if err != nil {
		return fmt.Errorf("setting final Return-Path: %w", err)
	}
	parsed, err = parser.Parse(rawMessage)
	if err != nil {
		return fmt.Errorf("%w: parsing final message: %v", errInvalidMessage, err)
	}

	// --- Check for MDN request ---
	mdnRequested := parsed.MDNRequestedBy != ""
	mdnAddress := parsed.MDNRequestedBy
	if mdnRequested {
		logging.Info(fmt.Sprintf("[smtp] MDN requested for %s to %s", parsed.MessageID, mdnAddress))
	}

	// --- Store the message for each recipient's account ---

	messageID := parsed.MessageID
	if messageID == "" {
		messageID = fmt.Sprintf("%d.%s@%s", time.Now().UnixNano(), clientIP, s.cfg.Server.Hostname)
	}

	// --- Check if this is a DSN message (bounce/failure notification) ---
	// DSNs arrive addressed to the original sender (not VERP address usually)
	// but contain information about which recipients failed
	isDSN := parser.IsDSNMessage(parsed.Subject, parsed.Headers, parsed.TextBody)
	var dsnReport *parser.DSNReport
	if isDSN {
		// Pass the full raw message (which includes MIME structure) to ParseDSN
		// so it can extract the message/delivery-status part
		dsnReport, _ = parser.ParseDSN(string(rawMessage))
		if dsnReport != nil {
			logging.Info(fmt.Sprintf("[smtp] [verp] received DSN: original-id=%s status=%s", dsnReport.OriginalMessageID, dsnReport.Status))
		}
	}
	type pendingDelivery struct {
		message           *store.Message
		recipient         string
		originalRecipient string
		notifySuccess     bool
	}
	var pending []pendingDelivery
	var bounces []store.InboundVERPBounce

	// Deliver to each recipient
	for _, rcpt := range rcptTo {
		// Note: DMARC enforcement is now done per-recipient via folder assignment below
		// p=reject and p=quarantine both result in messages going to spam folder
		// p=none messages go to inbox normally

		// Check if this recipient is a VERP bounce address
		issuedVERP, verpErr := s.db.LookupIssuedVERP(rcpt)
		if verpErr != nil {
			logging.Error(fmt.Sprintf("[smtp] [verp] lookup failed for %s: %v", rcpt, verpErr))
			return fmt.Errorf("looking up VERP recipient %s: %w", rcpt, verpErr)
		}
		if issuedVERP != nil {
			logging.Info(fmt.Sprintf("[smtp] [verp] detected bounce at VERP address %s for original recipient %s", rcpt, issuedVERP.Recipient))

			// Extract bounce code and type from DSN if available, otherwise use subject heuristics
			bounceCode := 0
			bounceType := "unknown"
			bounceReason := parsed.Subject

			if isDSN && dsnReport != nil {
				bounceType = parser.ExtractBounceType(dsnReport.Status)
				bounceCode = parser.ExtractSMTPCode(dsnReport.DiagnosticCode)
				if bounceCode == 0 && len(dsnReport.RecipientsStatus) > 0 {
					bounceCode = parser.ExtractSMTPCode(dsnReport.RecipientsStatus[0].DiagnosticCode)
				}
				bounceReason = dsnReport.DiagnosticCode
				if bounceReason == "" {
					bounceReason = dsnReport.Status
				}
			} else {
				// Fallback: try to extract SMTP code from message body or subject
				if strings.Contains(strings.ToLower(parsed.Subject), "permanent") || strings.Contains(strings.ToLower(parsed.Subject), "failed") {
					bounceType = "permanent"
					bounceCode = 550 // Generic permanent failure
				} else if strings.Contains(strings.ToLower(parsed.Subject), "temporary") || strings.Contains(strings.ToLower(parsed.Subject), "try again") {
					bounceType = "temporary"
					bounceCode = 421 // Service temporarily unavailable
				}
			}

			bounces = append(bounces, store.InboundVERPBounce{OriginalRecipient: issuedVERP.Recipient, SenderEmail: issuedVERP.Sender, BounceAddress: rcpt, BounceType: bounceType, BounceCode: bounceCode, BounceReason: bounceReason})

			// Skip account lookup for VERP addresses (they don't have accounts)
			continue
		}

		// DSNs sent to ordinary mailboxes are delivered as mail. Their body
		// claims are not authenticated bounce-tracker evidence; only an issued
		// VERP envelope address above can create a tracked bounce.

		// Check if DMARC failed for this domain
		if dmarcResult.Result == "fail" {
			switch dmarcResult.Policy {
			case "reject":
				logging.Warn(fmt.Sprintf("[smtp] DMARC p=reject: accepting but quarantining mail from %s (auth check failed)", fromDomain))
			case "quarantine":
				logging.Warn(fmt.Sprintf("[smtp] DMARC p=quarantine: accepting but marking suspicious from %s", fromDomain))
			case "none":
				logging.Info(fmt.Sprintf("[smtp] DMARC p=none: accepting in observation mode from %s", fromDomain))
			}
		}

		// Look up the account for this recipient
		account, err := s.db.GetDeliveryAccount(rcpt)
		if err != nil {
			logging.Warn(fmt.Sprintf("[smtp] account lookup error for %s: %v", rcpt, err))
			return err
		}
		if account == nil || !account.IsActive {
			return fmt.Errorf("recipient %s became unavailable after RCPT", rcpt)
		}

		accountID := account.ID

		// Determine folder based on auth results
		var folderID *int64

		// DMARC passes when either aligned SPF or aligned DKIM passes. ARC is
		// advisory evidence for forwarded mail and must not independently
		// quarantine an otherwise valid message. Message subjects, MIME types and
		// receipt headers are attacker-controlled and never bypass DMARC policy.
		authFailed := shouldQuarantineDMARC(dmarcResult.Result, dmarcResult.Policy)

		if authFailed {
			// Any auth failure → spam folder
			logging.Warn(fmt.Sprintf("[smtp] DMARC policy requested %s - SPF: %s, DKIM: %s, DMARC: %s",
				dmarcResult.Policy, spfResult, dkimResult, dmarcResult.Result))
			spamFolder, err := s.db.GetFolderByType(accountID, "spam")
			if err != nil {
				return fmt.Errorf("finding spam folder for account %d: %w", accountID, err)
			}
			if spamFolder == nil {
				return fmt.Errorf("spam folder missing for account %d", accountID)
			}
			folderID = &spamFolder.ID
			logging.Info(fmt.Sprintf("[smtp] message routed to spam folder=%d", spamFolder.ID))
		} else {
			// All auth passed - route to inbox
			inboxFolder, err := s.db.GetFolderByType(accountID, "inbox")
			if err != nil {
				return fmt.Errorf("finding inbox folder for account %d: %w", accountID, err)
			}
			if inboxFolder == nil {
				return fmt.Errorf("inbox folder missing for account %d", accountID)
			}
			folderID = &inboxFolder.ID
			logging.Info(fmt.Sprintf("[smtp] all auth passed (SPF: %s, DKIM: %s, DMARC: %s) - assigning to inbox folder=%d",
				spfResult, dkimResult, dmarcResult.Result, inboxFolder.ID))
		}

		recipientJSON, err := json.Marshal([]string{rcpt})
		if err != nil {
			return fmt.Errorf("encoding mailbox recipient: %w", err)
		}
		msg := &store.Message{
			AccountID: accountID,
			FolderID:  folderID,
			MessageID: messageID,
			Direction: "inbound",
			MailFrom:  mailFrom,
			// A mailbox copy must not disclose other envelope recipients,
			// including addresses omitted from the message's To/Cc fields.
			RcptTo:         string(recipientJSON),
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

		pending = append(pending, pendingDelivery{message: msg, recipient: rcpt,
			originalRecipient: sess.GetDSNOriginalRecipient(rcpt),
			notifySuccess:     mailFrom != "" && dsnFlagRequested(sess.GetDSNNotify(rcpt), "SUCCESS")})
	}
	messages := make([]*store.Message, len(pending))
	attachments := make([][]store.IMAPAppendAttachment, len(pending))
	var reports []*store.QueueEntry
	for index := range pending {
		messages[index] = pending[index].message
		for _, attachment := range parsed.Attachments {
			attachments[index] = append(attachments[index], store.IMAPAppendAttachment{Filename: attachment.Filename, ContentType: attachment.ContentType, Data: attachment.Data})
		}
		if pending[index].notifySuccess {
			report, err := s.prepareDeliveryDSN(mailFrom, pending[index].recipient, pending[index].originalRecipient, sess.GetDSNEnvelopeID(), rawMessage)
			if err != nil {
				return fmt.Errorf("preparing requested success DSN: %w", err)
			}
			reports = append(reports, report)
		}
	}
	messageIDs, err := s.db.SaveInboundDelivery(messages, reports, attachments, bounces)
	if err != nil {
		return err
	}
	// Feedback describes accepted mail and the disposition actually applied.
	// Keep it after the delivery commit so failed/retried transactions do not
	// inflate aggregate reports or claim that quarantined mail was rejected.
	disposition := "none"
	if shouldQuarantineDMARC(dmarcResult.Result, dmarcResult.Policy) {
		disposition = "quarantine"
	}
	if err := s.db.SaveDMARCFeedbackEvaluated(fromDomain, dmarcResult.PolicyDomain, clientIP, reportEnvelopeFromDomain(mailFrom), dkimResult, dkimDomain, dkimSelector, string(spfResult), spfDomain, "mfrom", disposition, dmarcResult.DKIMAligned, dmarcResult.SPFAligned); err != nil {
		logging.Warn(fmt.Sprintf("[smtp] warning: failed to save DMARC feedback: %v", err))
	}
	for index, delivery := range pending {
		msgID := messageIDs[index]
		logging.Info(fmt.Sprintf("[smtp] message stored id=%d account=%d from=%s to=%s",
			msgID, delivery.message.AccountID, mailFrom, delivery.recipient))
	}

	return nil
}

func shouldQuarantineDMARC(result auth.DMARCResult, policy auth.DMARCPolicy) bool {
	return result == auth.DMARCFail && policy != auth.PolicyNone
}

func dsnFlagRequested(value, wanted string) bool {
	for _, flag := range strings.Split(strings.ToUpper(value), ",") {
		if strings.TrimSpace(flag) == wanted {
			return true
		}
	}
	return false
}

// prepareDeliveryDSN signs a successful local-delivery report before the
// recipient and report queue entry are atomically committed. Its null reverse
// path prevents notification loops if delivery of the report later fails.
func (s *InboundServer) prepareDeliveryDSN(sender, recipient, originalRecipient, envID string, originalMessage []byte) (*store.QueueEntry, error) {
	report, err := reporting.BuildDSNMessageWithSender(s.cfg.Server.Hostname, s.cfg.Server.DSNSenderAddress(), recipient, originalRecipient, sender, "delivered", "delivered to local mailbox", 250, envID, "HDRS", originalMessage)
	if err != nil {
		return nil, err
	}
	raw := []byte(report)
	domain, err := s.db.GetDomainByName(s.cfg.Server.Domain)
	if err != nil {
		return nil, fmt.Errorf("loading DSN signing domain %s: %w", s.cfg.Server.Domain, err)
	}
	if domain != nil && domain.IsActive && domain.DKIMPrivateKey != "" {
		signer, err := auth.NewDKIMSignerFromPEM(domain.Domain, domain.DKIMSelector, []byte(domain.DKIMPrivateKey), domain.DKIMAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("initializing DSN DKIM signer: %w", err)
		}
		raw, err = signer.Sign(raw)
		if err != nil {
			return nil, fmt.Errorf("signing DSN: %w", err)
		}
	} else {
		logging.Warn(fmt.Sprintf("[smtp] sending requested success DSN without DKIM: no active signing key for %s", s.cfg.Server.Domain))
	}
	return &store.QueueEntry{
		MailFrom:          "",
		RcptTo:            sender,
		RawMessage:        raw,
		MaxAttempts:       s.cfg.Delivery.MaxRetries,
		NextRetry:         time.Now().UTC(),
		DSNNotify:         "NEVER",
		OriginalRecipient: sender,
	}, nil
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
	at := strings.LastIndexByte(addr, '@')
	if at >= 0 && at < len(addr)-1 {
		return addr[at+1:]
	}
	return addr
}

func spfIdentityDomain(mailFrom, helo string) string {
	if mailFrom == "" {
		// SPF checked postmaster@HELO for a null reverse-path.
		return strings.TrimSuffix(helo, ".")
	}
	return extractDomain(mailFrom)
}

// The report's envelope_from identifies the actual RFC5321 reverse-path, not
// the HELO-derived SPF identity used when that reverse-path is null.
func reportEnvelopeFromDomain(mailFrom string) string {
	if mailFrom == "" {
		return ""
	}
	return extractDomain(mailFrom)
}
