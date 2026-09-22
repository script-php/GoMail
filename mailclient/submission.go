package mailclient

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"gomail/logging"
	"gomail/store"
)

type submissionSession struct {
	server       *Server
	conn         net.Conn
	reader       *bufio.Reader
	writer       *bufio.Writer
	tls          bool
	ehlo         bool
	account      *store.Account
	mailFrom     string
	recipients   []string
	declaredSize int64
}

func (s *Server) handleSubmission(conn net.Conn) {
	p := &submissionSession{server: s, conn: conn, reader: bufio.NewReader(conn), writer: bufio.NewWriter(conn)}
	defer conn.Close()
	p.reply(220, fmt.Sprintf("%s ESMTP GoMail submission ready", s.cfg.Server.Hostname))
	for {
		_ = p.conn.SetReadDeadline(time.Now().Add(s.readTimeout()))
		line, err := p.reader.ReadString('\n')
		if err != nil {
			return
		}
		if len(line) > 1000 {
			p.reply(500, "Command line too long")
			return
		}
		line = strings.TrimRight(line, "\r\n")
		parts := strings.SplitN(line, " ", 2)
		command := strings.ToUpper(parts[0])
		argument := ""
		if len(parts) == 2 {
			argument = strings.TrimSpace(parts[1])
		}
		switch command {
		case "EHLO":
			p.handleEHLO(argument)
		case "HELO":
			p.ehlo = true
			p.resetEnvelope()
			p.reply(250, s.cfg.Server.Hostname)
		case "STARTTLS":
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
			p.handleDATA()
		case "RSET":
			p.resetEnvelope()
			p.reply(250, "OK")
		case "NOOP":
			p.reply(250, "OK")
		case "QUIT":
			p.reply(221, "Bye")
			return
		default:
			p.reply(502, "Command not implemented")
		}
	}
}

func (p *submissionSession) handleEHLO(argument string) {
	if argument == "" {
		p.reply(501, "EHLO requires a domain")
		return
	}
	p.ehlo = true
	p.resetEnvelope()
	lines := []string{p.server.cfg.Server.Hostname, fmt.Sprintf("SIZE %d", p.server.cfg.SMTP.MaxMessageSize), "8BITMIME", "PIPELINING"}
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
	p.conn = tlsConn
	p.reader = bufio.NewReader(tlsConn)
	p.writer = bufio.NewWriter(tlsConn)
	p.tls, p.ehlo, p.account = true, false, nil
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
	var username, password string
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
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil || account == nil {
		p.reply(535, "Authentication failed")
		return
	}
	p.account = account
	p.reply(235, "Authentication successful")
}

func (p *submissionSession) readAuthLine() (string, bool) {
	_ = p.conn.SetReadDeadline(time.Now().Add(p.server.readTimeout()))
	line, err := p.reader.ReadString('\n')
	if err != nil {
		return "", false
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "*" {
		p.reply(501, "Authentication cancelled")
		return "", false
	}
	return line, true
}

func (p *submissionSession) handleMAIL(argument string) {
	if p.account == nil {
		p.reply(530, "Authentication required")
		return
	}
	address, rest, ok := parsePath(argument, "FROM:")
	if !ok || !strings.EqualFold(address, p.account.Email) {
		p.reply(553, "MAIL FROM must match the authenticated account")
		return
	}
	p.declaredSize = 0
	for _, parameter := range strings.Fields(rest) {
		upper := strings.ToUpper(parameter)
		switch {
		case upper == "BODY=7BIT", upper == "BODY=8BITMIME":
		case strings.HasPrefix(upper, "SIZE="):
			size, err := strconv.ParseInt(strings.TrimPrefix(upper, "SIZE="), 10, 64)
			if err != nil || size < 0 || size > p.server.cfg.SMTP.MaxMessageSize {
				p.reply(552, "Invalid or excessive message size")
				return
			}
			p.declaredSize = size
		default:
			p.reply(555, "Unsupported MAIL FROM parameter")
			return
		}
	}
	p.mailFrom = p.account.Email
	p.recipients = nil
	p.reply(250, "OK")
}

func (p *submissionSession) handleRCPT(argument string) {
	if p.mailFrom == "" {
		p.reply(503, "MAIL FROM required")
		return
	}
	address, _, ok := parsePath(argument, "TO:")
	if !ok {
		p.reply(501, "Invalid RCPT TO")
		return
	}
	if _, err := mail.ParseAddress(address); err != nil {
		p.reply(553, "Invalid recipient address")
		return
	}
	if len(p.recipients) >= p.server.cfg.SMTP.MaxRecipients {
		p.reply(452, "Too many recipients")
		return
	}
	p.recipients = append(p.recipients, address)
	p.reply(250, "OK")
}

func (p *submissionSession) handleDATA() {
	if p.mailFrom == "" || len(p.recipients) == 0 {
		p.reply(503, "MAIL FROM and RCPT TO required")
		return
	}
	p.reply(354, "End data with <CRLF>.<CRLF>")
	message, err := p.readData()
	if err != nil {
		p.reply(552, err.Error())
		p.resetEnvelope()
		return
	}
	message = stripHeader(message, "bcc")
	if err := validateSubmittedFrom(message, p.account.Email); err != nil {
		p.reply(550, err.Error())
		p.resetEnvelope()
		return
	}
	received := fmt.Sprintf("Received: from authenticated-user by %s with ESMTPSA; %s\r\n", p.server.cfg.Server.Hostname, time.Now().Format(time.RFC1123Z))
	message = append([]byte(received), message...)
	if err := p.server.queue.Enqueue(p.account.Email, append([]string(nil), p.recipients...), message, p.account.ID); err != nil {
		logging.Warn(fmt.Sprintf("[submission] queue message for %s: %v", p.account.Email, err))
		p.reply(451, "Unable to queue message")
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
		line, err := p.reader.ReadString('\n')
		if err != nil {
			return nil, io.ErrUnexpectedEOF
		}
		if line == ".\r\n" || line == ".\n" {
			break
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		line = string(normalizeCRLF([]byte(strings.TrimRight(line, "\r\n")))) + "\r\n"
		if int64(result.Len()+len(line)) > limit {
			// Drain through the terminator so the session remains synchronized.
			for line != ".\r\n" && line != ".\n" {
				line, err = p.reader.ReadString('\n')
				if err != nil {
					break
				}
			}
			return nil, fmt.Errorf("message exceeds maximum size")
		}
		result.WriteString(line)
	}
	return result.Bytes(), nil
}

func (p *submissionSession) resetEnvelope() {
	p.mailFrom, p.recipients, p.declaredSize = "", nil, 0
}

func (p *submissionSession) reply(code int, message string) {
	_ = p.conn.SetWriteDeadline(time.Now().Add(p.server.writeTimeout()))
	_, _ = fmt.Fprintf(p.writer, "%d %s\r\n", code, message)
	_ = p.writer.Flush()
}

func (p *submissionSession) replyMulti(code int, lines []string) {
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
	end := strings.IndexByte(trimmed[start:], '>')
	if end < 0 {
		return "", "", false
	}
	end += start
	address := strings.TrimSpace(trimmed[start:end])
	if address == "" || strings.ContainsAny(address, "\r\n<>") {
		return "", "", false
	}
	return address, strings.TrimSpace(trimmed[end+1:]), true
}

func validateSubmittedFrom(raw []byte, authenticated string) error {
	message, err := mail.ReadMessage(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return fmt.Errorf("invalid message headers")
	}
	from := message.Header.Get("From")
	addresses, err := mail.ParseAddressList(from)
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
