package mailclient

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"gomail/delivery"
	"gomail/logging"
	"gomail/metrics"
	"gomail/security"
	"gomail/store"
)

type submissionSession struct {
	server       *Server
	conn         net.Conn
	reader       *bufio.Reader
	writer       *bufio.Writer
	tls          bool
	greeted      bool
	ehlo         bool
	account      *store.Account
	authMethod   string
	appSecretID  int64
	mailFrom     string
	recipients   []string
	dsnNotify    []string
	dsnOriginal  []string
	dsnReturn    string
	dsnEnvID     string
	declaredSize int64
	bodyMode     string
}

var errInvalidDATAFraming = errors.New("DATA requires CRLF line endings")
var errUnsynchronizedDATA = errors.New("DATA terminator not reached")

func (s *Server) handleSubmission(conn net.Conn) {
	p := &submissionSession{server: s, conn: conn, reader: bufio.NewReader(conn), writer: bufio.NewWriter(conn)}
	defer conn.Close()
	p.reply(220, fmt.Sprintf("%s ESMTP GoMail submission ready", s.cfg.Server.Hostname))
	for {
		_ = p.conn.SetReadDeadline(time.Now().Add(s.readTimeout()))
		line, err := security.ReadLineLimited(p.reader, security.SMTPCommandLineLimit)
		if err != nil {
			return
		}
		if len(line) > security.SMTPCommandLineLimit {
			p.reply(500, "Command line too long")
			return
		}
		line, err = security.ParseCRLFCommandLine(line)
		if err != nil {
			p.reply(500, "Command requires CRLF framing")
			return
		}
		parts := strings.SplitN(line, " ", 2)
		command := strings.ToUpper(parts[0])
		argument := ""
		if len(parts) == 2 {
			argument = strings.TrimSpace(parts[1])
		}
		if p.account != nil && !s.accountStillActive(p.account) {
			p.reply(421, "Account no longer active")
			return
		}
		if p.account != nil && p.authMethod != "" {
			passwordAllowed, appAllowed, policyErr := s.db.SMTPAllowedCredentials(p.account.ID)
			if policyErr != nil {
				p.reply(421, "Authentication policy unavailable")
				return
			}
			if p.authMethod == "password" && !passwordAllowed || p.authMethod == "app" && !appAllowed {
				p.reply(421, "SMTP login method disabled")
				return
			}
			if p.authMethod == "app" {
				active, checkErr := s.db.SMTPAppPasswordExists(p.account.ID, p.appSecretID)
				if checkErr != nil || !active {
					p.reply(421, "SMTP app credential revoked or unavailable")
					return
				}
			}
		}
		switch command {
		case "EHLO":
			p.handleEHLO(argument)
		case "HELO":
			if !validSubmissionGreeting(argument, false) {
				p.reply(501, "Invalid HELO domain")
				break
			}
			p.greeted, p.ehlo = true, false
			p.resetEnvelope()
			p.reply(250, s.cfg.Server.Hostname)
		case "STARTTLS":
			if argument != "" {
				p.reply(501, "STARTTLS does not take arguments")
				break
			}
			if !p.startTLS() {
				return
			}
		case "AUTH":
			p.authenticate(argument)
		case "MAIL":
			p.handleMAIL(argument)
		case "RCPT":
			p.handleRCPT(argument)
		case "DATA":
			if argument != "" {
				p.reply(501, "DATA does not take arguments")
				break
			}
			p.handleDATA()
		case "RSET":
			if argument != "" {
				p.reply(501, "RSET does not take arguments")
				break
			}
			p.resetEnvelope()
			p.reply(250, "OK")
		case "NOOP":
			p.reply(250, "OK")
		case "QUIT":
			if argument != "" {
				p.reply(501, "QUIT does not take arguments")
				break
			}
			p.reply(221, "Bye")
			return
		default:
			p.reply(502, "Command not implemented")
		}
	}
}

func (p *submissionSession) handleEHLO(argument string) {
	if !validSubmissionGreeting(argument, true) {
		p.reply(501, "Invalid EHLO domain or address literal")
		return
	}
	p.greeted, p.ehlo = true, true
	p.resetEnvelope()
	lines := []string{p.server.cfg.Server.Hostname, fmt.Sprintf("SIZE %d", p.server.cfg.SMTP.MaxMessageSize), "8BITMIME", "PIPELINING", "DSN"}
	if p.tls {
		lines = append(lines, "AUTH PLAIN LOGIN")
	} else {
		lines = append(lines, "STARTTLS")
	}
	p.replyMulti(250, lines)
}

func (p *submissionSession) startTLS() bool {
	if p.tls {
		p.reply(503, "Already using TLS")
		return true
	}
	if !p.ehlo {
		p.reply(503, "Send EHLO first")
		return true
	}
	p.reply(220, "Ready to start TLS")
	tlsConn := tls.Server(p.conn, p.server.tlsConfig.Clone())
	_ = tlsConn.SetDeadline(time.Now().Add(p.server.readTimeout()))
	if err := tlsConn.Handshake(); err != nil {
		logging.Warn(fmt.Sprintf("[submission] TLS handshake failed from %s: %v", p.conn.RemoteAddr(), err))
		return false
	}
	_ = tlsConn.SetDeadline(time.Time{})
	p.conn = tlsConn
	p.reader = bufio.NewReader(tlsConn)
	p.writer = bufio.NewWriter(tlsConn)
	p.tls, p.greeted, p.ehlo, p.account = true, false, false, nil
	p.authMethod, p.appSecretID = "", 0
	p.resetEnvelope()
	return true
}

func (p *submissionSession) authenticate(argument string) {
	if !p.tls {
		p.reply(538, "Encryption required for authentication")
		return
	}
	if !p.ehlo {
		p.reply(503, "Send EHLO first")
		return
	}
	if p.account != nil {
		p.reply(503, "Already authenticated")
		return
	}
	if !p.server.allowAuthentication(p.conn.RemoteAddr().String()) {
		p.reply(454, "Too many authentication attempts; try again later")
		return
	}
	fields := strings.Fields(argument)
	if len(fields) == 0 {
		p.reply(501, "AUTH mechanism required")
		return
	}
	var username, password, authorizationID string
	switch strings.ToUpper(fields[0]) {
	case "PLAIN":
		encoded := ""
		if len(fields) > 1 {
			encoded = fields[1]
		} else {
			p.reply(334, "")
			var ok bool
			encoded, ok = p.readAuthLine()
			if !ok {
				return
			}
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		parts := bytes.Split(decoded, []byte{0})
		if err != nil || len(parts) != 3 {
			p.reply(501, "Invalid AUTH PLAIN response")
			return
		}
		authorizationID = string(parts[0])
		username, password = string(parts[1]), string(parts[2])
	case "LOGIN":
		p.reply(334, base64.StdEncoding.EncodeToString([]byte("Username:")))
		encodedUser, ok := p.readAuthLine()
		if !ok {
			return
		}
		p.reply(334, base64.StdEncoding.EncodeToString([]byte("Password:")))
		encodedPassword, ok := p.readAuthLine()
		if !ok {
			return
		}
		userBytes, userErr := base64.StdEncoding.DecodeString(encodedUser)
		passwordBytes, passwordErr := base64.StdEncoding.DecodeString(encodedPassword)
		if userErr != nil || passwordErr != nil {
			p.reply(501, "Invalid AUTH LOGIN response")
			return
		}
		username, password = string(userBytes), string(passwordBytes)
	default:
		p.reply(504, "Unsupported authentication mechanism")
		return
	}
	account, err := p.server.db.GetAccountByEmail(strings.ToLower(username))
	hash := dummyBcryptHash
	if err == nil && account != nil {
		hash = account.PasswordHash
	}
	passwordErr := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		p.reply(454, "4.3.0 Authentication temporarily unavailable")
		return
	}
	matched := false
	var appSecretID int64
	if account != nil {
		passwordAllowed, appAllowed, policyErr := p.server.db.SMTPAllowedCredentials(account.ID)
		if policyErr != nil {
			p.reply(454, "4.3.0 Authentication temporarily unavailable")
			return
		}
		matched = passwordAllowed && passwordErr == nil
		if !matched && appAllowed {
			appSecretID, policyErr = p.server.db.VerifySMTPAppPassword(account.ID, password)
			if policyErr != nil {
				p.reply(454, "4.3.0 Authentication temporarily unavailable")
				return
			}
			matched = appSecretID != 0
		}
	}
	if !matched {
		p.server.recordAuthenticationFailure(p.conn.RemoteAddr().String())
		p.reply(535, "Authentication failed")
		return
	}
	// GoMail has no delegated submission identities. An explicit PLAIN
	// authorization identity must therefore name the authenticated account.
	if authorizationID != "" && !strings.EqualFold(authorizationID, account.Email) {
		p.server.recordAuthenticationFailure(p.conn.RemoteAddr().String())
		p.reply(535, "Authentication failed")
		return
	}
	p.account = account
	if appSecretID != 0 {
		p.authMethod, p.appSecretID = "app", appSecretID
	} else {
		p.authMethod = "password"
	}
	p.reply(235, "Authentication successful")
}

func (p *submissionSession) readAuthLine() (string, bool) {
	_ = p.conn.SetReadDeadline(time.Now().Add(p.server.readTimeout()))
	line, err := security.ReadLineLimited(p.reader, 1000)
	if err != nil {
		if errors.Is(err, security.ErrLineTooLong) {
			_ = p.conn.Close() // Unread AUTH bytes cannot be parsed as commands.
		}
		return "", false
	}
	line, err = security.ParseCRLFCommandLine(line)
	if err != nil {
		p.reply(501, "AUTH response requires CRLF framing")
		_ = p.conn.Close()
		return "", false
	}
	if line == "*" {
		p.reply(501, "Authentication cancelled")
		return "", false
	}
	return line, true
}

func (p *submissionSession) handleMAIL(argument string) {
	if !p.greeted && !p.ehlo {
		p.reply(503, "Send HELO or EHLO first")
		return
	}
	if p.account == nil {
		p.reply(530, "Authentication required")
		return
	}
	if p.mailFrom != "" {
		p.reply(503, "Mail transaction already open; send RSET first")
		return
	}
	address, rest, ok := parsePath(argument, "FROM:")
	if !ok || !strings.EqualFold(address, p.account.Email) {
		p.reply(553, "MAIL FROM must match the authenticated account")
		return
	}
	if !p.ehlo && strings.TrimSpace(rest) != "" {
		p.reply(555, "MAIL FROM parameters require EHLO")
		return
	}
	var bodyMode, dsnReturn, dsnEnvID string
	var declaredSize int64
	seen := make(map[string]bool)
	for _, parameter := range strings.Fields(rest) {
		upper := strings.ToUpper(parameter)
		key, _, _ := strings.Cut(upper, "=")
		if seen[key] {
			p.reply(501, "Duplicate MAIL FROM parameter")
			return
		}
		seen[key] = true
		switch {
		case upper == "BODY=7BIT", upper == "BODY=8BITMIME":
			bodyMode = strings.TrimPrefix(upper, "BODY=")
		case strings.HasPrefix(upper, "SIZE="):
			size, err := strconv.ParseInt(strings.TrimPrefix(upper, "SIZE="), 10, 64)
			if err != nil || size < 0 || size > p.server.cfg.SMTP.MaxMessageSize {
				p.reply(552, "Invalid or excessive message size")
				return
			}
			declaredSize = size
		case upper == "RET=FULL" || upper == "RET=HDRS":
			dsnReturn = strings.TrimPrefix(upper, "RET=")
		case strings.HasPrefix(upper, "ENVID="):
			value := parameter[len("ENVID="):]
			if len(value) == 0 || len(value) > 100 {
				p.reply(501, "Invalid ENVID parameter")
				return
			}
			decoded, err := decodeSubmissionXText(value)
			if err != nil || !validSubmissionDSNText(decoded) {
				p.reply(501, "Invalid ENVID parameter")
				return
			}
			dsnEnvID = decoded
		default:
			p.reply(555, "Unsupported MAIL FROM parameter")
			return
		}
	}
	p.mailFrom = p.account.Email
	p.bodyMode, p.declaredSize = bodyMode, declaredSize
	p.dsnReturn, p.dsnEnvID = dsnReturn, dsnEnvID
	p.reply(250, "OK")
}

func (p *submissionSession) handleRCPT(argument string) {
	if p.mailFrom == "" {
		p.reply(503, "MAIL FROM required")
		return
	}
	address, parameters, ok := parsePath(argument, "TO:")
	if !ok {
		p.reply(501, "Invalid RCPT TO")
		return
	}
	// This listener does not advertise SMTPUTF8. Do not accept an envelope
	// destination that a downstream non-SMTPUTF8 peer cannot receive.
	for _, b := range []byte(address) {
		if b >= 0x80 {
			p.reply(553, "SMTPUTF8 is required for internationalized recipient address")
			return
		}
	}
	if !p.ehlo && strings.TrimSpace(parameters) != "" {
		p.reply(555, "RCPT TO parameters require EHLO")
		return
	}
	notify, original := "", ""
	seen := make(map[string]bool)
	for _, parameter := range strings.Fields(parameters) {
		upper := strings.ToUpper(parameter)
		key, _, _ := strings.Cut(upper, "=")
		if seen[key] {
			p.reply(501, "Duplicate RCPT TO parameter")
			return
		}
		seen[key] = true
		switch {
		case strings.HasPrefix(upper, "NOTIFY="):
			var valid bool
			notify, valid = parseSubmissionNotify(parameter[len("NOTIFY="):])
			if !valid {
				p.reply(501, "Invalid NOTIFY parameter")
				return
			}
		case strings.HasPrefix(upper, "ORCPT="):
			var valid bool
			original, valid = parseSubmissionORCPT(parameter[len("ORCPT="):])
			if !valid {
				p.reply(501, "Invalid ORCPT parameter")
				return
			}
		default:
			p.reply(555, "Unsupported RCPT TO parameter")
			return
		}
	}
	if _, err := mail.ParseAddress(address); err != nil {
		p.reply(553, "Invalid recipient address")
		return
	}
	// A repeated RCPT must not create a second queued delivery. Preserve the
	// local-part's case: remote mailboxes may distinguish it (RFC 5321 §2.4).
	for _, existing := range p.recipients {
		if sameSMTPRecipient(existing, address) {
			p.reply(250, "OK (already a recipient)")
			return
		}
	}
	if len(p.recipients) >= p.server.cfg.SMTP.MaxRecipients {
		p.reply(452, "Too many recipients")
		return
	}
	if limits := p.server.db.OutboundLimits(); limits.Enabled && len(p.recipients) >= limits.MaxRecipientsPerMessage {
		p.reply(452, "4.7.0 Authenticated account recipient limit reached")
		return
	}
	p.recipients = append(p.recipients, address)
	p.dsnNotify = append(p.dsnNotify, notify)
	p.dsnOriginal = append(p.dsnOriginal, original)
	p.reply(250, "OK")
}

func sameSMTPRecipient(a, b string) bool {
	aAt, bAt := strings.LastIndexByte(a, '@'), strings.LastIndexByte(b, '@')
	return aAt >= 0 && bAt >= 0 && a[:aAt] == b[:bAt] && strings.EqualFold(a[aAt+1:], b[bAt+1:])
}

func parseSubmissionNotify(value string) (string, bool) {
	if strings.EqualFold(value, "NEVER") {
		return "NEVER", true
	}
	seen := make(map[string]bool)
	var flags []string
	for _, flag := range strings.Split(strings.ToUpper(value), ",") {
		if flag != "SUCCESS" && flag != "FAILURE" && flag != "DELAY" || seen[flag] {
			return "", false
		}
		seen[flag] = true
		flags = append(flags, flag)
	}
	return strings.Join(flags, ","), len(flags) > 0
}

func decodeSubmissionXText(value string) (string, error) {
	var decoded strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '+' {
			if i+2 >= len(value) {
				return "", fmt.Errorf("truncated xtext escape")
			}
			b, err := hex.DecodeString(value[i+1 : i+3])
			if err != nil {
				return "", err
			}
			decoded.WriteByte(b[0])
			i += 2
		} else {
			if value[i] < 33 || value[i] > 126 || value[i] == '=' {
				return "", fmt.Errorf("invalid xtext byte")
			}
			decoded.WriteByte(value[i])
		}
	}
	return decoded.String(), nil
}

func validSubmissionDSNText(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 32 || value[i] > 126 {
			return false
		}
	}
	return true
}

func parseSubmissionORCPT(value string) (string, bool) {
	if len(value) == 0 || len(value) > 500 {
		return "", false
	}
	typeName, encoded, ok := strings.Cut(value, ";")
	if !ok || !strings.EqualFold(typeName, "rfc822") {
		return "", false
	}
	decoded, err := decodeSubmissionXText(encoded)
	if err != nil || !validSubmissionDSNText(decoded) {
		return "", false
	}
	return decoded, true
}

func validSubmissionGreeting(argument string, allowLiteral bool) bool {
	if allowLiteral && len(argument) > 2 && argument[0] == '[' && argument[len(argument)-1] == ']' {
		literal := argument[1 : len(argument)-1]
		if strings.HasPrefix(strings.ToUpper(literal), "IPV6:") {
			ip := net.ParseIP(literal[5:])
			return ip != nil && ip.To4() == nil
		}
		ip := net.ParseIP(literal)
		return ip != nil && ip.To4() != nil
	}
	if argument == "" || len(argument) > 255 {
		return false
	}
	for _, label := range strings.Split(argument, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return false
			}
		}
	}
	return true
}

func (p *submissionSession) handleDATA() {
	if p.mailFrom == "" || len(p.recipients) == 0 {
		p.reply(503, "MAIL FROM and RCPT TO required")
		return
	}
	p.reply(354, "End data with <CRLF>.<CRLF>")
	message, err := p.readData()
	if err != nil {
		code := 552
		if errors.Is(err, errInvalidDATAFraming) {
			code = 554
		}
		p.reply(code, err.Error())
		p.resetEnvelope()
		if errors.Is(err, security.ErrLineTooLong) || errors.Is(err, errInvalidDATAFraming) || errors.Is(err, errUnsynchronizedDATA) || errors.Is(err, io.ErrUnexpectedEOF) {
			_ = p.conn.Close() // Unread DATA bytes must not become SMTP commands.
		}
		return
	}
	if err := validateSubmissionEncoding(message, p.bodyMode); err != nil {
		p.reply(554, err.Error())
		p.resetEnvelope()
		return
	}
	message = stripHeader(message, "bcc")
	message = stripHeader(message, "return-path")
	if !p.server.accountStillActive(p.account) {
		p.reply(421, "Account no longer active")
		p.resetEnvelope()
		return
	}
	if err := validateSubmittedFrom(message, p.account.Email); err != nil {
		p.reply(550, err.Error())
		p.resetEnvelope()
		return
	}
	received := fmt.Sprintf("Received: from authenticated-user by %s with ESMTPSA; %s\r\n", p.server.cfg.Server.Hostname, time.Now().Format(time.RFC1123Z))
	message = append([]byte(received), message...)
	dsn := delivery.SubmissionDSN{Notify: append([]string(nil), p.dsnNotify...), OriginalRecipient: append([]string(nil), p.dsnOriginal...), Return: p.dsnReturn, EnvelopeID: p.dsnEnvID}
	if err := p.server.queue.EnqueueSubmission(p.account.Email, append([]string(nil), p.recipients...), dsn, message, p.account.ID); err != nil {
		logging.Warn(fmt.Sprintf("[submission] queue message for %s: %v", p.account.Email, err))
		if errors.Is(err, store.ErrOutboundLimit) {
			metrics.IncOutboundLimit("submission")
			p.reply(452, "4.7.0 Outbound account limit exceeded; try again later")
		} else if errors.Is(err, store.ErrDiskPressure) {
			p.reply(452, "4.3.1 Insufficient system storage")
		} else if errors.Is(err, store.ErrQuotaExceeded) {
			metrics.IncQuota("submission")
			p.reply(452, "4.2.2 Mailbox quota exceeded")
		} else {
			p.reply(451, "Unable to queue message")
		}
	} else {
		p.reply(250, "Message accepted for delivery")
	}
	p.resetEnvelope()
}

func (p *submissionSession) readData() ([]byte, error) {
	var result bytes.Buffer
	limit := p.server.cfg.SMTP.MaxMessageSize
	for {
		_ = p.conn.SetReadDeadline(time.Now().Add(p.server.readTimeout()))
		line, err := security.ReadLineLimited(p.reader, 1001)
		if err != nil {
			if errors.Is(err, security.ErrLineTooLong) {
				return nil, err
			}
			return nil, io.ErrUnexpectedEOF
		}
		if !strings.HasSuffix(line, "\r\n") || strings.Contains(strings.TrimSuffix(line, "\r\n"), "\r") {
			return nil, errInvalidDATAFraming
		}
		if line == ".\r\n" {
			break
		}
		// RFC 5321 limits a transmitted DATA line to 1000 octets including
		// CRLF (and the dot-stuffing byte, if present). Reject it here rather
		// than accepting a message the outbound relay will later refuse.
		if len(line) > 1000 && !(strings.HasPrefix(line, "..") && len(line) == 1001) {
			return nil, fmt.Errorf("%w: DATA line exceeds 1000 octets", security.ErrLineTooLong)
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		// Preserve canonical DATA octets; mutating message text can break a
		// client-supplied signature even before GoMail signs the message.
		if int64(result.Len()+len(line)) > limit {
			// Drain through the terminator so the session remains synchronized.
			for line != ".\r\n" {
				line, err = security.ReadLineLimited(p.reader, 1001)
				if err != nil {
					return nil, fmt.Errorf("%w: message exceeds maximum size: %v", errUnsynchronizedDATA, err)
				}
				if !strings.HasSuffix(line, "\r\n") || strings.Contains(strings.TrimSuffix(line, "\r\n"), "\r") {
					return nil, fmt.Errorf("%w: invalid DATA framing", errUnsynchronizedDATA)
				}
			}
			return nil, fmt.Errorf("message exceeds maximum size")
		}
		result.WriteString(line)
	}
	return result.Bytes(), nil
}

func (p *submissionSession) resetEnvelope() {
	p.mailFrom, p.recipients, p.dsnNotify, p.dsnOriginal, p.dsnReturn, p.dsnEnvID, p.declaredSize, p.bodyMode = "", nil, nil, nil, "", "", 0, ""
}

func validateSubmissionEncoding(raw []byte, bodyMode string) error {
	boundary := bytes.Index(raw, []byte("\r\n\r\n"))
	if boundary < 0 {
		return fmt.Errorf("message has no header/body separator")
	}
	// Submission does not advertise SMTPUTF8, so UTF-8 header fields must
	// be encoded by the client (for example, as RFC 2047 encoded words).
	for _, b := range raw[:boundary] {
		if b >= 0x80 {
			return fmt.Errorf("SMTPUTF8 is required for UTF-8 message headers")
		}
	}
	for _, b := range raw[boundary+4:] {
		if b >= 0x80 && bodyMode != "8BITMIME" {
			return fmt.Errorf("BODY=8BITMIME is required for 8-bit content")
		}
	}
	return nil
}

func (p *submissionSession) reply(code int, message string) {
	_ = p.conn.SetWriteDeadline(time.Now().Add(p.server.writeTimeout()))
	_, _ = fmt.Fprintf(p.writer, "%d %s\r\n", code, message)
	_ = p.writer.Flush()
}

func (p *submissionSession) replyMulti(code int, lines []string) {
	_ = p.conn.SetWriteDeadline(time.Now().Add(p.server.writeTimeout()))
	for index, line := range lines {
		separator := "-"
		if index == len(lines)-1 {
			separator = " "
		}
		_, _ = fmt.Fprintf(p.writer, "%d%s%s\r\n", code, separator, line)
	}
	_ = p.writer.Flush()
}

func parsePath(argument, prefix string) (string, string, bool) {
	trimmed := strings.TrimSpace(argument)
	if !strings.HasPrefix(strings.ToUpper(trimmed), prefix+"<") {
		return "", "", false
	}
	start := len(prefix) + 1
	end := security.SMTPPathEnd(trimmed, start)
	if end < 0 {
		return "", "", false
	}
	address := strings.TrimSpace(trimmed[start:end])
	if address == "" || strings.ContainsAny(address, "\r\n") {
		return "", "", false
	}
	if end+1 < len(trimmed) && trimmed[end+1] != ' ' {
		return "", "", false
	}
	return address, strings.TrimSpace(trimmed[end+1:]), true
}

func validateSubmittedFrom(raw []byte, authenticated string) error {
	message, err := mail.ReadMessage(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return fmt.Errorf("invalid message headers")
	}
	fromFields := message.Header["From"]
	if len(fromFields) != 1 {
		return fmt.Errorf("message must have exactly one From header")
	}
	addresses, err := mail.ParseAddressList(fromFields[0])
	if err != nil || len(addresses) != 1 || !strings.EqualFold(addresses[0].Address, authenticated) {
		return fmt.Errorf("From header must match the authenticated account")
	}
	return nil
}

func stripHeader(raw []byte, name string) []byte {
	normalized := normalizeCRLF(raw)
	separator := []byte("\r\n\r\n")
	parts := bytes.SplitN(normalized, separator, 2)
	if len(parts) != 2 {
		return normalized
	}
	lines := bytes.Split(parts[0], []byte("\r\n"))
	var kept [][]byte
	skipping := false
	prefix := strings.ToLower(name) + ":"
	for _, line := range lines {
		continuation := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
		if continuation && skipping {
			continue
		}
		skipping = strings.HasPrefix(strings.ToLower(string(line)), prefix)
		if !skipping {
			kept = append(kept, line)
		}
	}
	return append(append(bytes.Join(kept, []byte("\r\n")), separator...), parts[1]...)
}
