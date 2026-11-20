package smtp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"gomail/security"
	"gomail/store"
)

// SessionState represents the current state of an SMTP conversation.
type SessionState int

var errSMTPDataTooLarge = errors.New("message exceeds maximum size")

const (
	StateGreeting SessionState = iota
	StateReady
	StateMail
	StateRcpt
	StateData
	StateQuit
)

// Session represents a single SMTP session with a connected client.
type Session struct {
	conn             net.Conn
	reader           *bufio.Reader
	writer           *bufio.Writer
	state            SessionState
	hostname         string
	domains          []string // all accepted domains
	postmasterDomain string
	accountExists    func(email string) (bool, error) // checks if a local account exists
	clientAddr       string
	clientIP         string
	ptrHostname      string // reverse DNS hostname (if verified)
	ptrValid         bool   // true if forward-confirmed reverse DNS
	ehlo             string
	greeted          bool
	esmtp            bool
	bdatFailed       bool
	mailFrom         string
	rcptTo           []string
	dsnNotify        map[string]string // map recipient -> notify flags (SUCCESS,FAILURE,DELAY)
	dsnOriginalRcpt  map[string]string // map recipient -> decoded ORCPT address
	dsnRET           string            // FULL or HDRS
	dsnEnvID         string            // Envelope ID
	data             bytes.Buffer
	tls              bool
	tlsConfig        *tls.Config
	maxSize          int64
	maxRcpt          int
	readTimeout      time.Duration
	writeTimeout     time.Duration
	smtputf8Enabled  bool      // true if client advertised SMTPUTF8 support
	bodyMode         string    // MAIL FROM BODY= value
	db               *store.DB // database reference for greylisting checks and domain lookups
}

// NewSession creates a new SMTP session for the given connection.
func NewSession(conn net.Conn, hostname string, domains []string, accountExists func(string) (bool, error), tlsCfg *tls.Config, maxSize int64, maxRcpt int, readTimeout, writeTimeout time.Duration, ptrHostname string, ptrValid bool, db *store.DB) *Session {
	remoteAddr := conn.RemoteAddr().String()
	ip, _, _ := net.SplitHostPort(remoteAddr)

	return &Session{
		conn:            conn,
		reader:          bufio.NewReader(conn),
		writer:          bufio.NewWriter(conn),
		state:           StateGreeting,
		hostname:        hostname,
		domains:         domains,
		accountExists:   accountExists,
		clientAddr:      remoteAddr,
		clientIP:        ip,
		ptrHostname:     ptrHostname,
		ptrValid:        ptrValid,
		tlsConfig:       tlsCfg,
		maxSize:         maxSize,
		maxRcpt:         maxRcpt,
		readTimeout:     readTimeout,
		writeTimeout:    writeTimeout,
		dsnNotify:       make(map[string]string),
		dsnOriginalRcpt: make(map[string]string),
		db:              db,
	}
}

// Handle runs the SMTP session to completion.
func (s *Session) Handle() {
	defer s.conn.Close()

	// Send greeting
	s.send(220, fmt.Sprintf("%s ESMTP GoMail ready", s.hostname))
	s.state = StateReady

	for s.state != StateQuit {
		s.conn.SetReadDeadline(time.Now().Add(s.readTimeout))

		line, err := security.ReadLineLimited(s.reader, security.SMTPCommandLineLimit)
		if err != nil {
			if err != io.EOF {
				log.Printf("[smtp] read error from %s: %v", s.clientAddr, err)
			}
			return
		}

		line, err = security.ParseCRLFCommandLine(line)
		if err != nil {
			s.sendEnhanced(500, "5.5.2", "Command requires CRLF framing")
			return
		}
		s.handleCommand(line)
	}
}

// handleCommand processes a single SMTP command.
func (s *Session) handleCommand(line string) {
	parts := strings.SplitN(line, " ", 2)
	cmd := strings.ToUpper(parts[0])
	var arg string
	if len(parts) > 1 {
		arg = parts[1]
	}

	switch cmd {
	case "EHLO":
		s.handleEHLO(arg)
	case "HELO":
		s.handleHELO(arg)
	case "STARTTLS":
		if arg != "" {
			s.sendEnhanced(501, "5.5.2", "STARTTLS does not take arguments")
			return
		}
		s.handleSTARTTLS()
	case "MAIL":
		s.handleMAIL(arg)
	case "RCPT":
		s.handleRCPT(arg)
	case "DATA":
		if arg != "" {
			s.sendEnhanced(501, "5.5.2", "DATA does not take arguments")
			return
		}
		s.handleDATA()
	case "BDAT":
		s.handleBDAT(arg)
	case "RSET":
		if arg != "" {
			s.sendEnhanced(501, "5.5.2", "RSET does not take arguments")
			return
		}
		s.handleRSET()
	case "NOOP":
		s.send(250, "OK")
	case "QUIT":
		if arg != "" {
			s.sendEnhanced(501, "5.5.2", "QUIT does not take arguments")
			return
		}
		s.send(221, fmt.Sprintf("%s closing connection", s.hostname))
		s.state = StateQuit
	case "VRFY":
		s.send(252, "Cannot VRFY user, but will accept message and attempt delivery")
	case "HELP", "EXPN":
		s.send(502, "Command not implemented")
	default:
		// Apply tarpitting if enabled for any domain
		if len(s.domains) > 0 {
			s.applyTarpitting(s.domains[0], cmd)
		}
		s.send(500, "Command not recognized")
	}
}

func (s *Session) handleEHLO(arg string) {
	// Validate HELO/EHLO argument per RFC 5321 §4.1.1.1
	if err := s.validateHeloEhlo(arg); err != nil {
		s.send(501, fmt.Sprintf("Bad EHLO syntax: %v", err))
		return
	}

	s.ehlo = arg
	s.greeted = true
	s.esmtp = true
	s.reset()
	s.state = StateReady

	// Check if client supports SMTPUTF8
	// This is detected from the EHLO argument in the actual handshake
	// For now, we always advertise it (RFC 6531)

	lines := []string{
		fmt.Sprintf("%s greets %s", s.hostname, arg),
		fmt.Sprintf("SIZE %d", s.maxSize),
		"8BITMIME",
		"PIPELINING",
		"DSN",
		"ENHANCEDSTATUSCODES",
		"SMTPUTF8",
		"CHUNKING",
	}

	if !s.tls && s.tlsConfig != nil {
		lines = append(lines, "STARTTLS")
	}

	// Send multiline response
	for i, line := range lines {
		if i == len(lines)-1 {
			s.send(250, line)
		} else {
			s.sendMulti(250, line)
		}
	}
}

func (s *Session) handleHELO(arg string) {
	// Validate HELO/EHLO argument per RFC 5321 §4.1.1.1
	if err := s.validateHeloEhlo(arg); err != nil {
		s.send(501, fmt.Sprintf("Bad HELO syntax: %v", err))
		return
	}

	s.ehlo = arg
	s.greeted = true
	s.esmtp = false
	s.reset()
	s.state = StateReady
	s.send(250, fmt.Sprintf("%s Hello %s", s.hostname, arg))
}

// validateHeloEhlo validates HELO/EHLO argument per RFC 5321 §4.1.1.1
// Must be either a domain name or an address literal
func (s *Session) validateHeloEhlo(arg string) error {
	if arg == "" {
		return fmt.Errorf("empty HELO/EHLO argument")
	}

	// Check for address literal format: [IPv4] or [IPv6:...]
	if len(arg) > 2 && arg[0] == '[' && arg[len(arg)-1] == ']' {
		inner := arg[1 : len(arg)-1]
		// RFC 5321 requires the IPv6: tag on IPv6 address literals.
		if strings.HasPrefix(strings.ToUpper(inner), "IPV6:") {
			// IPv6 address
			if ip := net.ParseIP(inner[5:]); ip != nil && ip.To4() == nil {
				log.Printf("[smtp] HELO/EHLO validation passed for %s from %s (IPv6 literal)", arg, s.clientAddr)
				return nil
			}
			return fmt.Errorf("invalid IPv6 address literal: %s", inner)
		}
		// IPv4 check
		if ip := net.ParseIP(inner); ip != nil && ip.To4() != nil {
			log.Printf("[smtp] HELO/EHLO validation passed for %s from %s (IPv4 literal)", arg, s.clientAddr)
			return nil
		}
		return fmt.Errorf("invalid IPv4 address literal: %s", inner)
	}

	// Domain name check: must contain at least one dot (FQDN) or be "localhost"
	if arg == "localhost" {
		log.Printf("[smtp] HELO/EHLO validation passed for 'localhost' from %s", s.clientAddr)
		return nil
	}

	if !strings.Contains(arg, ".") {
		return fmt.Errorf("domain name must be a FQDN (contain at least one dot), got: %s", arg)
	}

	// Basic sanity check: domain should not start with dot or hyphen
	if strings.HasPrefix(arg, ".") || strings.HasPrefix(arg, "-") {
		return fmt.Errorf("invalid domain format: starts with invalid character")
	}

	// Check each label is valid
	labels := strings.Split(arg, ".")
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("domain contains empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("domain label exceeds 63 chars: %s", label)
		}
		// Labels should be alphanumeric + hyphens (but not start/end with hyphen)
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("domain label cannot start or end with hyphen: %s", label)
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-') {
				return fmt.Errorf("invalid domain label character: %q", char)
			}
		}
	}

	log.Printf("[smtp] HELO/EHLO validation passed for %s from %s (domain name)", arg, s.clientAddr)
	return nil
}

func (s *Session) handleSTARTTLS() {
	if s.state != StateReady {
		s.sendEnhanced(503, "5.5.1", "STARTTLS is not allowed during a mail transaction")
		return
	}
	if !s.esmtp {
		s.sendEnhanced(503, "5.5.1", "EHLO required before STARTTLS")
		return
	}
	if s.tls {
		s.send(503, "Already in TLS mode")
		return
	}
	if s.tlsConfig == nil {
		s.send(454, "TLS not available")
		return
	}

	s.send(220, "Ready to start TLS")
	s.writer.Flush()

	tlsConn := tls.Server(s.conn, s.tlsConfig)
	if s.readTimeout > 0 {
		_ = tlsConn.SetDeadline(time.Now().Add(s.readTimeout))
	}
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[smtp] TLS handshake failed from %s: %v", s.clientAddr, err)
		s.state = StateQuit
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	s.conn = tlsConn
	s.reader = bufio.NewReader(tlsConn)
	s.writer = bufio.NewWriter(tlsConn)
	s.tls = true
	s.reset()
	s.ehlo = ""
	s.greeted = false
	s.esmtp = false
	s.state = StateGreeting // RFC 3207 requires a fresh EHLO/HELO after TLS.

	log.Printf("[smtp] TLS established with %s (version: %x)", s.clientAddr, tlsConn.ConnectionState().Version)
}

func (s *Session) handleMAIL(arg string) {
	if s.state != StateReady {
		s.sendEnhanced(503, "5.5.1", "Bad sequence of commands")
		return
	}
	if !s.greeted {
		s.sendEnhanced(503, "5.5.1", "HELO or EHLO required before MAIL")
		return
	}

	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(arg)), "FROM:<") {
		s.sendEnhanced(501, "5.5.2", "Syntax error in MAIL FROM")
		return
	}
	from := extractAddress(arg, "FROM:")
	if from == "" && !strings.Contains(strings.ToUpper(arg), "FROM:<>") {
		s.sendEnhanced(501, "5.5.2", "Syntax error in MAIL FROM")
		return
	}
	if from != "" {
		address, parseErr := mail.ParseAddress(from)
		if parseErr != nil || address.Address != from {
			s.sendEnhanced(501, "5.1.7", "Invalid reverse-path")
			return
		}
	}

	params, err := parseESMTPParameters(arg)
	if err != nil {
		s.sendEnhanced(501, "5.5.2", err.Error())
		return
	}
	if len(params) > 0 && !s.esmtp {
		s.sendEnhanced(555, "5.5.4", "EHLO required for MAIL parameters")
		return
	}
	mailSMTPUTF8 := false
	mailBodyMode := ""
	for key, value := range params {
		upperValue := strings.ToUpper(value)
		switch key {
		case "SMTPUTF8":
			if value != "" {
				s.sendEnhanced(501, "5.5.4", "SMTPUTF8 does not take a value")
				return
			}
			mailSMTPUTF8 = true
		case "BODY":
			if upperValue != "7BIT" && upperValue != "8BITMIME" {
				s.sendEnhanced(501, "5.5.4", "Invalid BODY parameter")
				return
			}
			mailBodyMode = upperValue
		case "SIZE":
			n, e := strconv.ParseInt(value, 10, 64)
			if e != nil || n < 0 {
				s.sendEnhanced(501, "5.5.4", "Invalid SIZE parameter")
				return
			}
			if n > s.maxSize {
				s.sendEnhanced(552, "5.3.4", "Message exceeds maximum size")
				return
			}
		case "RET":
			if upperValue != "FULL" && upperValue != "HDRS" {
				s.sendEnhanced(501, "5.5.4", "Invalid RET parameter")
				return
			}
		case "ENVID":
			if value == "" || len(value) > 100 {
				s.sendEnhanced(501, "5.5.4", "Invalid ENVID parameter")
				return
			}
		default:
			s.sendEnhanced(555, "5.5.4", "Unsupported MAIL FROM parameter")
			return
		}
	}
	if hasNonASCII(from) && !mailSMTPUTF8 {
		s.sendEnhanced(553, "5.6.7", "SMTPUTF8 is required for internationalized address")
		return
	}

	mailEnvID := ""
	if value := params["ENVID"]; value != "" {
		decoded, decodeErr := decodeXText(value)
		if decodeErr != nil {
			s.sendEnhanced(501, "5.5.4", "Invalid ENVID parameter")
			return
		}
		for _, b := range []byte(decoded) {
			if b != '\t' && (b < 32 || b > 126) {
				s.sendEnhanced(501, "5.5.4", "Invalid ENVID parameter")
				return
			}
		}
		mailEnvID = decoded
	}

	s.smtputf8Enabled = mailSMTPUTF8
	s.bodyMode = mailBodyMode
	s.dsnRET = strings.ToUpper(params["RET"])
	s.dsnEnvID = mailEnvID
	s.mailFrom = from
	s.state = StateMail
	s.sendEnhanced(250, "2.1.0", "OK")
}

func (s *Session) handleRCPT(arg string) {
	if s.state != StateMail && s.state != StateRcpt {
		s.sendEnhanced(503, "5.5.1", "Bad sequence of commands")
		return
	}

	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(arg)), "TO:<") {
		s.sendEnhanced(501, "5.5.2", "Syntax error in RCPT TO")
		return
	}
	to := extractAddress(arg, "TO:")
	if strings.EqualFold(to, "postmaster") {
		domain := s.postmasterDomain
		if domain == "" && len(s.domains) > 0 {
			domain = s.domains[0]
		}
		if domain != "" {
			to = "postmaster@" + domain
		}
	}
	if to == "" {
		s.sendEnhanced(501, "5.5.2", "Syntax error in RCPT TO")
		return
	}
	// SMTP forward-paths contain a mailbox, not RFC 5322 header comments
	// or folding whitespace. Validate before account and alias lookup.
	address, parseErr := mail.ParseAddress(to)
	if parseErr != nil || address.Address != to {
		s.sendEnhanced(553, "5.1.3", "Invalid recipient address")
		return
	}
	if hasNonASCII(to) && !s.smtputf8Enabled {
		s.sendEnhanced(553, "5.6.7", "SMTPUTF8 is required for internationalized address")
		return
	}
	params, err := parseESMTPParameters(arg)
	if err != nil {
		s.sendEnhanced(501, "5.5.2", err.Error())
		return
	}
	if len(params) > 0 && !s.esmtp {
		s.sendEnhanced(555, "5.5.4", "EHLO required for RCPT parameters")
		return
	}
	var decodedORCPT string
	for key, value := range params {
		upperValue := strings.ToUpper(value)
		switch key {
		case "NOTIFY":
			if !validNotify(upperValue) {
				s.sendEnhanced(501, "5.5.4", "Invalid NOTIFY parameter")
				return
			}
		case "ORCPT":
			if value == "" || len(value) > 500 || !strings.Contains(value, ";") {
				s.sendEnhanced(501, "5.5.4", "Invalid ORCPT parameter")
				return
			}
			parts := strings.SplitN(value, ";", 2)
			if parts[0] == "" || parts[1] == "" {
				s.sendEnhanced(501, "5.5.4", "Invalid ORCPT parameter")
				return
			}
			switch strings.ToLower(parts[0]) {
			case "rfc822":
				decodedORCPT, err = decodeXText(parts[1])
				if err == nil {
					for _, b := range []byte(decodedORCPT) {
						if b < 32 || b > 126 {
							err = fmt.Errorf("non-ASCII or control byte in rfc822 ORCPT")
							break
						}
					}
				}
			case "utf-8":
				var address string
				address, err = decodeUnitext(parts[1], s.smtputf8Enabled)
				decodedORCPT = "utf-8;" + address
			default:
				err = fmt.Errorf("unsupported ORCPT address type")
			}
			if err != nil {
				s.sendEnhanced(501, "5.5.4", "Invalid ORCPT parameter")
				return
			}
		default:
			s.sendEnhanced(555, "5.5.4", "Unsupported RCPT TO parameter")
			return
		}
	}

	// Check if recipient is for one of our domains
	at := strings.LastIndexByte(to, '@')
	if at < 0 || at == len(to)-1 {
		s.sendEnhanced(550, "5.1.3", fmt.Sprintf("Invalid address: %s", to))
		return
	}
	recipientDomain, domainErr := idna.Lookup.ToASCII(to[at+1:])
	if domainErr != nil || recipientDomain == "" {
		s.sendEnhanced(553, "5.1.3", "Invalid recipient domain")
		return
	}
	recipientDomain = strings.ToLower(recipientDomain)
	to = to[:at+1] + recipientDomain
	accepted := false
	for _, d := range s.domains {
		if strings.EqualFold(d, recipientDomain) {
			accepted = true
			break
		}
	}
	if !accepted {
		s.applyTarpitting(recipientDomain, "RCPT")
		s.sendEnhanced(550, "5.7.1", fmt.Sprintf("User not local; not accepting mail for %s", to))
		return
	}
	// A repeated envelope recipient is still acknowledged, but must not
	// produce another mailbox copy or overwrite the first RCPT's DSN options.
	for _, existing := range s.rcptTo {
		if strings.EqualFold(existing, to) {
			s.sendEnhanced(250, "2.1.5", "OK (already a recipient)")
			return
		}
	}

	// A bounce address is not a mailbox. Accept it only if we actually issued
	// that exact return path for an outbound queue entry.
	issuedVERP := false
	if s.db != nil {
		var issued *store.IssuedVERP
		issued, err = s.db.LookupIssuedVERP(to)
		if err != nil {
			s.sendEnhanced(451, "4.3.0", "Temporary recipient lookup failure")
			return
		}
		issuedVERP = issued != nil
	}
	// Verify the specific account exists for ordinary mail.
	if !issuedVERP && s.accountExists != nil {
		exists, lookupErr := s.accountExists(to)
		if lookupErr != nil {
			s.sendEnhanced(451, "4.3.0", "Temporary recipient lookup failure")
			return
		}
		if !exists {
			s.applyTarpitting(recipientDomain, "RCPT")
			s.sendEnhanced(550, "5.1.1", fmt.Sprintf("No such user: %s", to))
			return
		}
	}

	// Check greylisting if enabled for this domain
	if s.db != nil && s.mailFrom != "" {
		domain, err := s.db.GetDomainByName(recipientDomain)
		if err != nil {
			log.Printf("[smtp] domain policy lookup error for %s: %v", recipientDomain, err)
			s.sendEnhanced(451, "4.3.0", "Temporary recipient policy lookup failure")
			return
		}
		if domain != nil && domain.GreylistingEnabled {
			// Check greylisting status
			status, err := s.db.CheckGreylist(recipientDomain, s.clientIP, s.mailFrom, to, domain.GreylistingDelayMins)
			if err != nil {
				log.Printf("[smtp] greylisting check error for %s from %s: %v", to, s.clientIP, err)
				s.sendEnhanced(451, "4.3.0", "Temporary recipient policy lookup failure")
				return
			}
			if status != nil {
				if status.IsNew {
					log.Printf("[smtp] greylisting: new triplet (IP=%s, FROM=%s, TO=%s), temporary rejection", s.clientIP, s.mailFrom, to)
					s.sendEnhanced(450, "4.2.0", "Mailbox temporarily unavailable")
					return
				}
				if !status.IsWhitelisted && !status.DelayExpired {
					log.Printf("[smtp] greylisting: triplet still in delay period (IP=%s, FROM=%s, TO=%s), temporary rejection", s.clientIP, s.mailFrom, to)
					s.sendEnhanced(450, "4.2.0", "Mailbox temporarily unavailable")
					return
				}
				if status.DelayExpired && !status.IsWhitelisted {
					log.Printf("[smtp] greylisting: triplet whitelisted after delay (IP=%s, FROM=%s, TO=%s)", s.clientIP, s.mailFrom, to)
				}
			}
		}
	}

	if len(s.rcptTo) >= s.maxRcpt {
		s.sendEnhanced(452, "4.5.3", "Too many recipients")
		return
	}

	s.rcptTo = append(s.rcptTo, to)
	if notify := strings.ToUpper(params["NOTIFY"]); notify != "" && notify != "NEVER" {
		s.dsnNotify[to] = notify
	}
	if decodedORCPT != "" {
		s.dsnOriginalRcpt[to] = decodedORCPT
	}

	s.state = StateRcpt
	s.sendEnhanced(250, "2.1.5", "OK")
}

// readDataLine bounds accumulation even when a sender never sends a newline.
func (s *Session) readDataLine(limit int64) ([]byte, error) {
	var line []byte
	for {
		fragment, err := s.reader.ReadSlice('\n')
		if int64(len(line))+int64(len(fragment)) > limit {
			return nil, errSMTPDataTooLarge
		}
		line = append(line, fragment...)
		if err == bufio.ErrBufferFull {
			continue
		}
		return line, err
	}
}

func (s *Session) handleDATA() {
	if s.state != StateRcpt || len(s.rcptTo) == 0 {
		s.sendEnhanced(503, "5.5.1", "Bad sequence of commands")
		return
	}

	s.send(354, "Start mail input; end with <CRLF>.<CRLF>")

	s.data.Reset()
	var totalSize int64

	for {
		s.conn.SetReadDeadline(time.Now().Add(s.readTimeout))

		line, err := s.readDataLine(s.maxSize - totalSize + 3)
		if err != nil {
			log.Printf("[smtp] data read error from %s: %v", s.clientAddr, err)
			if errors.Is(err, errSMTPDataTooLarge) {
				s.sendEnhanced(552, "5.3.4", "Message exceeds maximum size")
			}
			s.data.Reset()
			s.state = StateQuit
			return
		}

		// RFC 5321 requires CRLF framing. In particular, LF-only ".\n"
		// must never terminate DATA.
		if bytes.Equal(line, []byte(".\r\n")) {
			break
		}
		if !bytes.HasSuffix(line, []byte("\r\n")) || bytes.IndexByte(line[:len(line)-2], '\r') >= 0 {
			s.sendEnhanced(554, "5.6.0", "DATA requires CRLF line endings")
			s.data.Reset()
			s.state = StateQuit
			return
		}
		stuffed := len(line) > 0 && line[0] == '.'
		if len(line) > 1000 && !(stuffed && len(line) == 1001) {
			s.sendEnhanced(552, "5.3.4", "DATA line exceeds 1000 octets")
			s.data.Reset()
			s.state = StateQuit
			return
		}

		// Dot-stuffing: remove leading dot
		if stuffed {
			line = line[1:]
		}

		totalSize += int64(len(line))
		if totalSize > s.maxSize {
			s.sendEnhanced(552, "5.3.4", "Message exceeds maximum size")
			s.reset()
			s.state = StateQuit
			return
		}

		s.data.Write(line)
	}

	s.state = StateReady
	// Data is now in s.data — will be processed by the inbound handler
}

func (s *Session) handleBDAT(arg string) {
	if !s.esmtp {
		s.sendEnhanced(503, "5.5.1", "EHLO required before BDAT")
		return
	}
	if s.bdatFailed {
		// A sender may have pipelined more chunks before seeing our failure.
		// RFC 3030 requires consuming each declared chunk before replying.
		length, _, err := parseBDATArguments(arg)
		if err != nil {
			s.sendEnhanced(501, "5.5.2", err.Error())
			return
		}
		s.conn.SetReadDeadline(time.Now().Add(s.readTimeout))
		if _, err := io.CopyN(io.Discard, s.reader, length); err != nil {
			s.state = StateQuit
			return
		}
		s.sendEnhanced(503, "5.5.1", "RSET required after failed BDAT")
		return
	}
	if s.state != StateRcpt && s.state != StateData {
		length, _, err := parseBDATArguments(arg)
		if err != nil {
			s.sendEnhanced(501, "5.5.2", err.Error())
			return
		}
		// Even an out-of-sequence BDAT carries exactly length data octets.
		// Consume them before replying so the next command stays framed.
		s.conn.SetReadDeadline(time.Now().Add(s.readTimeout))
		if _, err := io.CopyN(io.Discard, s.reader, length); err != nil {
			s.state = StateQuit
			return
		}
		s.sendEnhanced(503, "5.5.1", "Bad sequence of commands")
		return
	}

	// Parse "BDAT <length> [LAST]"
	length, isLast, err := parseBDATArguments(arg)
	if err != nil {
		s.sendEnhanced(501, "5.5.2", err.Error())
		return
	}

	// Stream-discard an oversized chunk before replying, as RFC 3030 requires.
	// CopyN uses a bounded buffer, and the read deadline bounds an incomplete
	// or deliberately enormous declaration without allocating its full size.
	if length > s.maxSize-int64(s.data.Len()) {
		s.conn.SetReadDeadline(time.Now().Add(s.readTimeout))
		if _, err := io.CopyN(io.Discard, s.reader, length); err != nil {
			s.data.Reset()
			s.state = StateQuit
			return
		}
		s.data.Reset()
		s.bdatFailed = true
		s.state = StateData
		s.sendEnhanced(552, "5.3.4", "Message exceeds maximum size")
		return
	}

	// Read exactly length bytes into the already bounded message buffer. Avoid
	// allocating a second, chunk-sized copy for every concurrent SMTP client.
	s.conn.SetReadDeadline(time.Now().Add(s.readTimeout))
	_, err = io.CopyN(&s.data, s.reader, length)
	if err != nil {
		log.Printf("[smtp] BDAT read error from %s: %v", s.clientAddr, err)
		s.sendEnhanced(452, "4.3.0", "Failed to read chunk")
		s.data.Reset()
		s.state = StateQuit
		return
	}

	// If LAST flag received, message transmission is complete
	if isLast {
		s.state = StateReady
		// Data is now in s.data — will be processed by the inbound handler
		// Don't send response here; let inbound.go handle it after processMessage
	} else {
		// Expect more BDAT chunks - send OK and keep state as StateData
		s.sendEnhanced(250, "2.0.0", "OK")
		s.state = StateData
	}
}

func parseBDATArguments(arg string) (int64, bool, error) {
	parts := strings.Fields(arg)
	if len(parts) < 1 || len(parts) > 2 || (len(parts) == 2 && !strings.EqualFold(parts[1], "LAST")) {
		return 0, false, fmt.Errorf("syntax error in BDAT command")
	}
	for _, c := range parts[0] {
		if c < '0' || c > '9' {
			return 0, false, fmt.Errorf("invalid chunk size")
		}
	}
	length, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("invalid chunk size")
	}
	return length, len(parts) == 2, nil
}

func (s *Session) rejectBDATChunkForRateLimit(arg string) {
	length, _, err := parseBDATArguments(arg)
	if err != nil {
		s.sendEnhanced(501, "5.5.2", err.Error())
		return
	}
	s.conn.SetReadDeadline(time.Now().Add(s.readTimeout))
	if _, err := io.CopyN(io.Discard, s.reader, length); err != nil {
		s.state = StateQuit
		return
	}
	s.data.Reset()
	s.bdatFailed = true
	s.state = StateData
	s.sendEnhanced(451, "4.5.3", "Too many messages, try again later")
}

func (s *Session) handleRSET() {
	s.reset()
	s.bdatFailed = false
	s.state = StateReady
	s.sendEnhanced(250, "2.0.0", "OK")
}

func (s *Session) reset() {
	s.mailFrom = ""
	s.rcptTo = nil
	s.dsnNotify = make(map[string]string)
	s.dsnOriginalRcpt = make(map[string]string)
	s.dsnRET = ""
	s.dsnEnvID = ""
	s.data.Reset()
	s.smtputf8Enabled = false
	s.bodyMode = ""
	s.bdatFailed = false
}

func parseESMTPParameters(arg string) (map[string]string, error) {
	start := strings.IndexByte(arg, '<')
	end := -1
	if start >= 0 {
		end = security.SMTPPathEnd(arg, start+1)
	}
	if end < 0 {
		return nil, fmt.Errorf("path must end with >")
	}
	suffix := arg[end+1:]
	if suffix != "" && suffix[0] != ' ' {
		return nil, fmt.Errorf("ESMTP parameters require a space after the path")
	}
	fields := strings.Fields(suffix)
	out := make(map[string]string, len(fields))
	for _, field := range fields {
		parts := strings.SplitN(field, "=", 2)
		key := strings.ToUpper(parts[0])
		value := ""
		if len(parts) == 2 {
			value = parts[1]
		}
		if key == "" {
			return nil, fmt.Errorf("empty ESMTP parameter")
		}
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("duplicate ESMTP parameter %s", key)
		}
		out[key] = value
	}
	return out, nil
}

func validNotify(value string) bool {
	if value == "NEVER" {
		return true
	}
	if value == "" {
		return false
	}
	seen := map[string]bool{}
	for _, v := range strings.Split(value, ",") {
		if v != "SUCCESS" && v != "FAILURE" && v != "DELAY" {
			return false
		}
		if seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}

func (s *Session) validateMessageEncoding() error {
	raw := s.data.Bytes()
	// CHUNKING without BINARYMIME still carries canonical text MIME. DATA
	// framing was checked while reading, but BDAT must be checked here too.
	if bytes.IndexByte(raw, 0) >= 0 {
		return fmt.Errorf("BINARYMIME is required for NUL octets")
	}
	if err := validateSMTPDataLines(raw); err != nil {
		return err
	}
	boundary := bytes.Index(raw, []byte("\r\n\r\n"))
	separator := 4
	if boundary < 0 {
		// RFC 5322 permits a message consisting solely of header fields.
		// Without a blank line, all bytes belong to the header section.
		if !bytes.HasSuffix(raw, []byte("\r\n")) {
			return fmt.Errorf("malformed message: unterminated header section")
		}
		boundary = len(raw)
		separator = 0
	}
	if has8Bit(raw[:boundary]) && !s.smtputf8Enabled {
		return fmt.Errorf("SMTPUTF8 is required for UTF-8 message headers")
	}
	if has8Bit(raw[boundary+separator:]) && s.bodyMode != "8BITMIME" {
		return fmt.Errorf("BODY=8BITMIME is required for 8-bit content")
	}
	return nil
}

func (s *Session) send(code int, message string) {
	s.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	fmt.Fprintf(s.writer, "%d %s\r\n", code, message)
	s.writer.Flush()
}

func (s *Session) sendEnhanced(code int, status, message string) {
	s.send(code, status+" "+message)
}

func (s *Session) sendMulti(code int, message string) {
	s.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	fmt.Fprintf(s.writer, "%d-%s\r\n", code, message)
	s.writer.Flush()
}

// applyTarpitting checks if tarpitting is enabled for a domain and applies delay if warranted
func (s *Session) applyTarpitting(recipientDomain, commandType string) {
	if s.db == nil {
		return
	}

	domain, err := s.db.GetDomainByName(recipientDomain)
	if err != nil || domain == nil || !domain.TarpittingEnabled {
		return
	}

	// Check current failure count for this IP with domain's max delay setting
	delay, err := s.db.CheckTarpittingWithMaxDelay(recipientDomain, s.clientIP, domain.TarpittingMaxDelaySecs)
	if err != nil || delay < 0 { // -1 means whitelisted
		return
	}

	// Apply delay if > 0 seconds
	if delay > 0 {
		log.Printf("[smtp] tarpitting: applying %ds delay to %s from %s (command: %s)", delay, recipientDomain, s.clientIP, commandType)
		time.Sleep(time.Duration(delay) * time.Second)
	}

	// Increment failure counter
	if err := s.db.IncrementTarpittingFailure(recipientDomain, s.clientIP, commandType); err != nil {
		log.Printf("[smtp] tarpitting: error incrementing failure count for %s: %v", s.clientIP, err)
	}
}

// extractAddress parses an address from MAIL FROM:<addr> or RCPT TO:<addr>.
func extractAddress(arg, prefix string) string {
	upper := strings.ToUpper(arg)
	idx := strings.Index(upper, prefix)
	if idx == -1 {
		return ""
	}
	rest := arg[idx+len(prefix):]
	rest = strings.TrimSpace(rest)

	// Extract from angle brackets
	if strings.HasPrefix(rest, "<") {
		end := security.SMTPPathEnd(rest, 1)
		if end == -1 {
			return ""
		}
		return rest[1:end]
	}

	// No angle brackets — take until space or end
	parts := strings.Fields(rest)
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// GetMailFrom returns the envelope sender.
func (s *Session) GetMailFrom() string { return s.mailFrom }

// GetRcptTo returns the envelope recipients.
func (s *Session) GetRcptTo() []string { return s.rcptTo }

// GetData returns the raw message data.
func (s *Session) GetData() []byte { return s.data.Bytes() }

// GetClientIP returns the connecting client's IP.
func (s *Session) GetClientIP() string { return s.clientIP }

// IsTLS returns whether the session is encrypted.
func (s *Session) IsTLS() bool { return s.tls }

// GetDSNNotify returns the DSN NOTIFY flags for a recipient (or empty string if none).
func (s *Session) GetDSNNotify(recipient string) string {
	return s.dsnNotify[recipient]
}

// GetDSNOriginalRecipient returns the decoded RFC 3461 ORCPT value.
func (s *Session) GetDSNOriginalRecipient(recipient string) string {
	return s.dsnOriginalRcpt[recipient]
}

func (s *Session) GetDSNReturnType() string { return s.dsnRET }
func (s *Session) GetDSNEnvelopeID() string { return s.dsnEnvID }

// parseDSNMailParams parses DSN parameters from MAIL FROM command.
// Format: MAIL FROM:<addr> [RET=FULL|HDRS] [ENVID=id]
func (s *Session) parseDSNMailParams(arg string) {
	// Look for RET parameter
	if strings.Contains(strings.ToUpper(arg), "RET=") {
		idx := strings.Index(strings.ToUpper(arg), "RET=")
		if idx != -1 {
			rest := arg[idx+4:]
			if idx2 := strings.IndexAny(rest, " \t"); idx2 != -1 {
				s.dsnRET = rest[:idx2]
			} else {
				s.dsnRET = rest
			}
		}
	}

	// Look for ENVID parameter
	if strings.Contains(strings.ToUpper(arg), "ENVID=") {
		idx := strings.Index(strings.ToUpper(arg), "ENVID=")
		if idx != -1 {
			rest := arg[idx+6:]
			if idx2 := strings.IndexAny(rest, " \t"); idx2 != -1 {
				s.dsnEnvID = rest[:idx2]
			} else {
				s.dsnEnvID = rest
			}
		}
	}
}

// parseDSNRcptParams parses DSN parameters from RCPT TO command.
// Format: RCPT TO:<addr> [NOTIFY=SUCCESS|FAILURE|DELAY|NEVER] [ORCPT=rfc822;addr]
func (s *Session) parseDSNRcptParams(recipient, arg string) {
	var notify string

	// Look for NOTIFY parameter
	upperArg := strings.ToUpper(arg)
	if strings.Contains(upperArg, "NOTIFY=") {
		idx := strings.Index(upperArg, "NOTIFY=")
		if idx != -1 {
			rest := arg[idx+7:]
			if idx2 := strings.IndexAny(rest, " \t"); idx2 != -1 {
				notify = rest[:idx2]
			} else {
				notify = rest
			}
		}
	}

	// Store NOTIFY flags for this recipient
	if notify != "" && notify != "NEVER" {
		s.dsnNotify[recipient] = notify
	}
}
