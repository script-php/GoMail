package smtp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// SessionState represents the current state of an SMTP conversation.
type SessionState int

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
	conn            net.Conn
	reader          *bufio.Reader
	writer          *bufio.Writer
	state           SessionState
	hostname        string
	domains         []string                // all accepted domains
	accountExists   func(email string) bool // checks if a local account exists
	clientAddr      string
	clientIP        string
	ptrHostname     string // reverse DNS hostname (if verified)
	ptrValid        bool   // true if forward-confirmed reverse DNS
	ehlo            string
	mailFrom        string
	rcptTo          []string
	dsnNotify       map[string]string // map recipient -> notify flags (SUCCESS,FAILURE,DELAY)
	dsnRET          string            // FULL or HDRS
	dsnEnvID        string            // Envelope ID
	data            bytes.Buffer
	tls             bool
	tlsConfig       *tls.Config
	maxSize         int64
	maxRcpt         int
	readTimeout     time.Duration
	writeTimeout    time.Duration
	smtputf8Enabled bool // true if client advertised SMTPUTF8 support
}

// NewSession creates a new SMTP session for the given connection.
func NewSession(conn net.Conn, hostname string, domains []string, accountExists func(string) bool, tlsCfg *tls.Config, maxSize int64, maxRcpt int, readTimeout, writeTimeout time.Duration, ptrHostname string, ptrValid bool) *Session {
	remoteAddr := conn.RemoteAddr().String()
	ip, _, _ := net.SplitHostPort(remoteAddr)

	return &Session{
		conn:          conn,
		reader:        bufio.NewReader(conn),
		writer:        bufio.NewWriter(conn),
		state:         StateGreeting,
		hostname:      hostname,
		domains:       domains,
		accountExists: accountExists,
		clientAddr:    remoteAddr,
		clientIP:      ip,
		ptrHostname:   ptrHostname,
		ptrValid:      ptrValid,
		tlsConfig:     tlsCfg,
		maxSize:       maxSize,
		maxRcpt:       maxRcpt,
		readTimeout:   readTimeout,
		writeTimeout:  writeTimeout,
		dsnNotify:     make(map[string]string),
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

		line, err := s.reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("[smtp] read error from %s: %v", s.clientAddr, err)
			}
			return
		}

		line = strings.TrimRight(line, "\r\n")
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
		s.handleSTARTTLS()
	case "MAIL":
		s.handleMAIL(arg)
	case "RCPT":
		s.handleRCPT(arg)
	case "DATA":
		s.handleDATA()
	case "BDAT":
		s.handleBDAT(arg)
	case "RSET":
		s.handleRSET()
	case "NOOP":
		s.send(250, "OK")
	case "QUIT":
		s.send(221, fmt.Sprintf("%s closing connection", s.hostname))
		s.state = StateQuit
	case "VRFY":
		s.send(252, "Cannot VRFY user, but will accept message and attempt delivery")
	default:
		s.send(502, "Command not recognized")
	}
}

func (s *Session) handleEHLO(arg string) {
	s.ehlo = arg
	s.reset()
	s.state = StateReady

	// Check if client supports SMTPUTF8
	// This is detected from the EHLO argument in the actual handshake
	// For now, we always advertise it (RFC 6531)

	lines := []string{
		fmt.Sprintf("%s greets %s", s.hostname, arg),
		fmt.Sprintf("SIZE %d", s.maxSize),
		"8BITMIME",
		"ENHANCEDSTATUSCODES",
		"PIPELINING",
		"DSN",
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
	s.ehlo = arg
	s.reset()
	s.state = StateReady
	s.send(250, fmt.Sprintf("%s Hello %s", s.hostname, arg))
}

func (s *Session) handleSTARTTLS() {
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
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[smtp] TLS handshake failed from %s: %v", s.clientAddr, err)
		return
	}

	s.conn = tlsConn
	s.reader = bufio.NewReader(tlsConn)
	s.writer = bufio.NewWriter(tlsConn)
	s.tls = true
	s.reset()

	log.Printf("[smtp] TLS established with %s (version: %x)", s.clientAddr, tlsConn.ConnectionState().Version)
}

func (s *Session) handleMAIL(arg string) {
	if s.state != StateReady {
		s.send(503, "Bad sequence of commands")
		return
	}

	from := extractAddress(arg, "FROM:")
	if from == "" && !strings.Contains(strings.ToUpper(arg), "FROM:<>") {
		s.send(501, "Syntax error in MAIL FROM")
		return
	}

	// Check for UTF8 parameter (RFC 6531)
	if strings.Contains(strings.ToUpper(arg), "UTF8") {
		s.smtputf8Enabled = true
	}

	// Parse DSN parameters (RET, ENVID)
	s.parseDSNMailParams(arg)

	s.mailFrom = from
	s.state = StateMail
	s.send(250, "OK")
}

func (s *Session) handleRCPT(arg string) {
	if s.state != StateMail && s.state != StateRcpt {
		s.send(503, "Bad sequence of commands")
		return
	}

	to := extractAddress(arg, "TO:")
	if to == "" {
		s.send(501, "Syntax error in RCPT TO")
		return
	}

	// Check if recipient is for one of our domains
	parts := strings.SplitN(to, "@", 2)
	if len(parts) != 2 {
		s.send(550, fmt.Sprintf("Invalid address: %s", to))
		return
	}
	recipientDomain := strings.ToLower(parts[1])
	accepted := false
	for _, d := range s.domains {
		if strings.EqualFold(d, recipientDomain) {
			accepted = true
			break
		}
	}
	if !accepted {
		s.send(550, fmt.Sprintf("User not local; not accepting mail for %s", to))
		return
	}

	// Verify the specific account exists
	if s.accountExists != nil && !s.accountExists(to) {
		s.send(550, fmt.Sprintf("No such user: %s", to))
		return
	}

	if len(s.rcptTo) >= s.maxRcpt {
		s.send(452, "Too many recipients")
		return
	}

	s.rcptTo = append(s.rcptTo, to)

	// Parse DSN parameters (NOTIFY, ORCPT)
	s.parseDSNRcptParams(to, arg)

	s.state = StateRcpt
	s.send(250, "OK")
}

func (s *Session) handleDATA() {
	if s.state != StateRcpt || len(s.rcptTo) == 0 {
		s.send(503, "Bad sequence of commands")
		return
	}

	s.send(354, "Start mail input; end with <CRLF>.<CRLF>")

	s.data.Reset()
	var totalSize int64

	for {
		s.conn.SetReadDeadline(time.Now().Add(s.readTimeout))

		line, err := s.reader.ReadBytes('\n')
		if err != nil {
			log.Printf("[smtp] data read error from %s: %v", s.clientAddr, err)
			return
		}

		// Check for end of data
		trimmed := bytes.TrimRight(line, "\r\n")
		if string(trimmed) == "." {
			break
		}

		// Dot-stuffing: remove leading dot
		if len(trimmed) > 0 && trimmed[0] == '.' {
			line = line[1:]
		}

		totalSize += int64(len(line))
		if totalSize > s.maxSize {
			s.send(552, "Message exceeds maximum size")
			s.reset()
			return
		}

		s.data.Write(line)
	}

	s.state = StateReady
	// Data is now in s.data — will be processed by the inbound handler
}

func (s *Session) handleBDAT(arg string) {
	if s.state != StateRcpt && s.state != StateData {
		s.send(503, "Bad sequence of commands")
		return
	}

	// Parse "BDAT <length> [LAST]"
	parts := strings.Fields(arg)
	if len(parts) < 1 {
		s.send(501, "Syntax error in BDAT command")
		return
	}

	var length int64
	_, err := fmt.Sscanf(parts[0], "%d", &length)
	if err != nil || length < 0 {
		s.send(501, "Invalid chunk size")
		return
	}

	isLast := len(parts) > 1 && strings.ToUpper(parts[1]) == "LAST"

	// Read exactly 'length' bytes from connection
	s.conn.SetReadDeadline(time.Now().Add(s.readTimeout))
	chunk := make([]byte, length)

	n, err := io.ReadFull(s.reader, chunk)
	if err != nil {
		log.Printf("[smtp] BDAT read error from %s: %v", s.clientAddr, err)
		s.send(452, "Failed to read chunk")
		return
	}

	// Check total size including this chunk
	totalSize := int64(s.data.Len()) + int64(n)
	if totalSize > s.maxSize {
		s.send(552, "Message exceeds maximum size")
		s.reset()
		return
	}

	// Append chunk to message data
	s.data.Write(chunk)

	// If LAST flag received, message transmission is complete
	if isLast {
		s.state = StateReady
		// Data is now in s.data — will be processed by the inbound handler
		// Don't send response here; let inbound.go handle it after processMessage
	} else {
		// Expect more BDAT chunks - send OK and keep state as StateData
		s.send(250, "OK")
		s.state = StateData
	}
}

func (s *Session) handleRSET() {
	s.reset()
	s.state = StateReady
	s.send(250, "OK")
}

func (s *Session) reset() {
	s.mailFrom = ""
	s.rcptTo = nil
	s.dsnNotify = make(map[string]string)
	s.dsnRET = ""
	s.dsnEnvID = ""
	s.data.Reset()
}

func (s *Session) send(code int, message string) {
	s.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	fmt.Fprintf(s.writer, "%d %s\r\n", code, message)
	s.writer.Flush()
}

func (s *Session) sendMulti(code int, message string) {
	s.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	fmt.Fprintf(s.writer, "%d-%s\r\n", code, message)
	s.writer.Flush()
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
		end := strings.IndexByte(rest, '>')
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
