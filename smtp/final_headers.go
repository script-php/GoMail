package smtp

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
)

// RemoveExternalAuthenticationResults removes assertions supplied by an
// untrusted SMTP peer before GoMail adds its own authentication results.
// No upstream SMTP peers are configured as trusted authentication services.
func RemoveExternalAuthenticationResults(raw []byte) ([]byte, error) {
	boundary := bytes.Index(raw, []byte("\r\n\r\n"))
	if boundary < 0 {
		return nil, fmt.Errorf("message has no header/body separator")
	}
	var result bytes.Buffer
	lines := bytes.Split(raw[:boundary], []byte("\r\n"))
	skip := false
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			name, _, found := bytes.Cut(line, []byte(":"))
			skip = found && bytes.EqualFold(name, []byte("Authentication-Results"))
		}
		if !skip {
			result.Write(line)
			result.WriteString("\r\n")
		}
	}
	result.WriteString("\r\n")
	result.Write(raw[boundary+4:])
	return result.Bytes(), nil
}

// FinalDeliveryReturnPath replaces untrusted Return-Path fields with the
// envelope reverse-path. Call this only when delivering to a local mailbox.
func FinalDeliveryReturnPath(raw []byte, mailFrom string) ([]byte, error) {
	boundary := bytes.Index(raw, []byte("\r\n\r\n"))
	if boundary < 0 {
		return nil, fmt.Errorf("message has no header/body separator")
	}
	var result bytes.Buffer
	path := "<>"
	if mailFrom != "" {
		if strings.ContainsAny(mailFrom, "\r\n<>") {
			return nil, fmt.Errorf("invalid envelope reverse-path")
		}
		path = "<" + mailFrom + ">"
	}
	result.WriteString("Return-Path: " + path + "\r\n")
	lines := bytes.Split(raw[:boundary], []byte("\r\n"))
	skip := false
	for _, line := range lines {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if !skip {
				result.Write(line)
				result.WriteString("\r\n")
			}
			continue
		}
		name, _, found := bytes.Cut(line, []byte(":"))
		skip = found && bytes.EqualFold(name, []byte("Return-Path"))
		if !skip {
			result.Write(line)
			result.WriteString("\r\n")
		}
	}
	result.WriteString("\r\n")
	result.Write(raw[boundary+4:])
	return result.Bytes(), nil
}

func inboundReceivedHeader(hostname, clientIP string, recipients []string, encrypted bool, now time.Time) string {
	protocol := "SMTP"
	if encrypted {
		protocol = "ESMTPS"
	}
	address := clientIP
	if ip := net.ParseIP(clientIP); ip != nil {
		if ip.To4() != nil {
			address = "[" + ip.String() + "]"
		} else {
			address = "[IPv6:" + ip.String() + "]"
		}
	}
	header := fmt.Sprintf("Received: from %s\r\n\tby %s\r\n\twith %s\r\n\tid %d@%s",
		address, hostname, protocol, now.UnixNano(), hostname)
	// RFC 5321 permits exactly one path in FOR. Omitting it for multiple
	// recipients also keeps envelope-only Bcc recipients private.
	if len(recipients) == 1 {
		header += "\r\n\tfor <" + recipients[0] + ">"
	}
	return header + ";\r\n\t" + now.Format(time.RFC1123Z) + "\r\n"
}
