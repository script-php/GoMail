package mailclient

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"gomail/logging"
	"gomail/security"
	"gomail/store"
)

const dummyBcryptHash = "$2a$10$7EqJtq98hPqEX7fNZaFWoO5Jv5bR9Qn7I9I4nYcWfJwP9gE3v3f3e"

type pop3Session struct {
	server   *Server
	conn     net.Conn
	reader   *bufio.Reader
	writer   *bufio.Writer
	username string
	account  *store.Account
	messages []store.POP3Message
	deleted  map[int]bool
	locked   bool
}

func (s *Server) handlePOP3(conn net.Conn) {
	session := &pop3Session{server: s, conn: conn, reader: bufio.NewReader(conn), writer: bufio.NewWriter(conn), deleted: make(map[int]bool)}
	defer func() {
		if session.locked && session.account != nil {
			s.maildrops.Delete(session.account.ID)
		}
		_ = conn.Close()
	}()
	session.ok("GoMail POP3 server ready")
	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout()))
		line, err := security.ReadLineLimited(session.reader, 512)
		if err != nil {
			return
		}
		if len(line) > 512 {
			session.err("command line too long")
			return
		}
		line, err = security.ParseCRLFCommandLine(line)
		if err != nil {
			session.err("command requires CRLF framing")
			return
		}
		parts := strings.SplitN(line, " ", 2)
		command := strings.ToUpper(parts[0])
		argument := ""
		if len(parts) == 2 {
			argument = parts[1]
			if command != "PASS" {
				argument = strings.TrimSpace(argument)
			}
		}
		if session.account != nil && !s.accountStillActive(session.account) {
			session.err("account no longer active")
			return
		}
		if session.account == nil {
			if session.authorization(command, argument) {
				return
			}
		} else if session.transaction(command, argument) {
			return
		}
	}
}

func (p *pop3Session) authorization(command, argument string) bool {
	switch command {
	case "CAPA":
		p.ok("Capability list follows")
		p.multi([]byte("USER\r\nUIDL\r\nTOP\r\nIMPLEMENTATION GoMail\r\n"))
	case "USER":
		if argument == "" {
			p.err("missing username")
		} else {
			p.username = strings.ToLower(argument)
			p.ok("password required")
		}
	case "PASS":
		if p.username == "" || argument == "" {
			p.err("USER and PASS are required")
			break
		}
		if !p.server.allowAuthentication(p.conn.RemoteAddr().String()) {
			p.err("too many authentication attempts; try again later")
			break
		}
		account, err := p.server.db.GetAccountByEmail(p.username)
		hash := dummyBcryptHash
		if err == nil && account != nil {
			hash = account.PasswordHash
		}
		passwordErr := bcrypt.CompareHashAndPassword([]byte(hash), []byte(argument))
		if err != nil {
			p.err("authentication temporarily unavailable")
			break
		}
		if passwordErr != nil || account == nil {
			p.server.recordAuthenticationFailure(p.conn.RemoteAddr().String())
			p.err("authentication failed")
			break
		}
		if _, loaded := p.server.maildrops.LoadOrStore(account.ID, struct{}{}); loaded {
			p.err("maildrop already locked")
			break
		}
		messages, err := p.server.db.ListPOP3Messages(account.ID)
		if err != nil {
			p.server.maildrops.Delete(account.ID)
			p.err("unable to open maildrop")
			break
		}
		p.account, p.messages, p.locked = account, messages, true
		p.ok(fmt.Sprintf("maildrop has %d messages (%d octets)", p.visibleCount(), p.visibleSize()))
	case "QUIT":
		p.ok("bye")
		return true
	case "NOOP":
		p.ok("OK")
	default:
		p.err("authenticate first")
	}
	return false
}

func (p *pop3Session) transaction(command, argument string) bool {
	switch command {
	case "STAT":
		p.ok(fmt.Sprintf("%d %d", p.visibleCount(), p.visibleSize()))
	case "LIST", "UIDL":
		p.list(command, argument)
	case "RETR":
		if message, _, ok := p.message(argument); ok {
			raw, err := p.server.db.GetPOP3MessageRaw(p.account.ID, message.ID)
			if err != nil {
				p.err("message temporarily unavailable")
				break
			}
			p.ok(fmt.Sprintf("%d octets", message.Octets))
			p.multi(raw)
		}
	case "TOP":
		fields := strings.Fields(argument)
		if len(fields) != 2 {
			p.err("usage: TOP message lines")
			break
		}
		lines, err := strconv.Atoi(fields[1])
		if err != nil || lines < 0 {
			p.err("invalid line count")
			break
		}
		if message, _, ok := p.message(fields[0]); ok {
			raw, err := p.server.db.GetPOP3MessageRaw(p.account.ID, message.ID)
			if err != nil {
				p.err("message temporarily unavailable")
				break
			}
			p.ok("top of message follows")
			p.multi(topMessage(raw, lines))
		}
	case "DELE":
		if _, index, ok := p.message(argument); ok {
			p.deleted[index] = true
			p.ok("message marked for deletion")
		}
	case "RSET":
		p.deleted = make(map[int]bool)
		p.ok(fmt.Sprintf("maildrop has %d messages (%d octets)", p.visibleCount(), p.visibleSize()))
	case "NOOP":
		p.ok("OK")
	case "CAPA":
		p.ok("Capability list follows")
		p.multi([]byte("USER\r\nUIDL\r\nTOP\r\nIMPLEMENTATION GoMail\r\n"))
	case "QUIT":
		var ids []int64
		for index := range p.deleted {
			ids = append(ids, p.messages[index].ID)
		}
		if err := p.server.db.DeletePOP3Messages(p.account.ID, ids); err != nil {
			logging.Warn(fmt.Sprintf("[pop3] update maildrop for %s: %v", p.account.Email, err))
			p.err("maildrop update failed; messages not deleted")
		} else {
			p.ok("bye")
		}
		return true
	default:
		p.err("unknown command")
	}
	return false
}

func (p *pop3Session) list(command, argument string) {
	if argument != "" {
		message, index, ok := p.message(argument)
		if !ok {
			return
		}
		value := strconv.Itoa(message.Octets)
		if command == "UIDL" {
			value = fmt.Sprintf("gomail-%d", message.ID)
		}
		p.ok(fmt.Sprintf("%d %s", index+1, value))
		return
	}
	p.ok("scan listing follows")
	var out strings.Builder
	for index, message := range p.messages {
		if p.deleted[index] {
			continue
		}
		value := strconv.Itoa(message.Octets)
		if command == "UIDL" {
			value = fmt.Sprintf("gomail-%d", message.ID)
		}
		fmt.Fprintf(&out, "%d %s\r\n", index+1, value)
	}
	p.multi([]byte(out.String()))
}

func (p *pop3Session) message(argument string) (store.POP3Message, int, bool) {
	number, err := strconv.Atoi(argument)
	index := number - 1
	if err != nil || index < 0 || index >= len(p.messages) || p.deleted[index] {
		p.err("no such message")
		return store.POP3Message{}, 0, false
	}
	return p.messages[index], index, true
}

func (p *pop3Session) visibleCount() int {
	return len(p.messages) - len(p.deleted)
}

func (p *pop3Session) visibleSize() int {
	total := 0
	for index, message := range p.messages {
		if !p.deleted[index] {
			total += message.Octets
		}
	}
	return total
}

func (p *pop3Session) ok(message string)  { p.reply("+OK " + message) }
func (p *pop3Session) err(message string) { p.reply("-ERR " + message) }

func (p *pop3Session) reply(message string) {
	_ = p.conn.SetWriteDeadline(time.Now().Add(p.server.writeTimeout()))
	_, _ = p.writer.WriteString(message + "\r\n")
	_ = p.writer.Flush()
}

func (p *pop3Session) multi(data []byte) {
	data = bytes.TrimSuffix(normalizeCRLF(data), []byte("\r\n"))
	lines := bytes.Split(data, []byte("\r\n"))
	if len(data) > 0 {
		for _, line := range lines {
			if len(line) > 0 && line[0] == '.' {
				_ = p.writer.WriteByte('.')
			}
			_, _ = p.writer.Write(line)
			_, _ = p.writer.WriteString("\r\n")
		}
	}
	_, _ = p.writer.WriteString(".\r\n")
	_ = p.writer.Flush()
}

// POP3 size excludes transparency dots but includes the CRLF transmitted for
// each message line. Keep this calculation aligned with multi's framing.
func pop3MessageOctets(raw []byte) int {
	data := bytes.TrimSuffix(normalizeCRLF(raw), []byte("\r\n"))
	if len(data) == 0 {
		return 0
	}
	return len(data) + 2
}

func normalizeCRLF(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
	return bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
}

func topMessage(raw []byte, bodyLines int) []byte {
	normalized := normalizeCRLF(raw)
	separator := []byte("\r\n\r\n")
	parts := bytes.SplitN(normalized, separator, 2)
	if len(parts) == 1 {
		return normalized
	}
	body := bytes.Split(parts[1], []byte("\r\n"))
	if bodyLines < len(body) {
		body = body[:bodyLines]
	}
	return append(append(append([]byte{}, parts[0]...), separator...), bytes.Join(body, []byte("\r\n"))...)
}
