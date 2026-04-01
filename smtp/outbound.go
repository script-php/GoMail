package smtp

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	godns "gomail/dns"
)

// SendMail delivers a message to a remote SMTP server via MX lookup.
// This is used by the delivery worker for outbound messages.
func SendMail(from, to string, msg []byte, hostname string, tlsCfg *tls.Config) error {
	// Extract recipient domain
	parts := strings.SplitN(to, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid recipient address: %s", to)
	}
	domain := parts[1]

	// MX lookup
	mxRecords, err := godns.LookupMX(domain)
	if err != nil {
		return fmt.Errorf("MX lookup for %s: %w", domain, err)
	}

	// Try each MX in preference order
	var lastErr error
	for _, mx := range mxRecords {
		err := deliverToHost(mx.Host, from, to, msg, hostname, tlsCfg)
		if err == nil {
			return nil // Success
		}
		lastErr = err
		log.Printf("[smtp] delivery to %s failed: %v, trying next MX", mx.Host, err)
	}

	return fmt.Errorf("all MX hosts failed for %s: %w", domain, lastErr)
}

// deliverToHost connects to a specific SMTP host and delivers the message.
func deliverToHost(host, from, to string, msg []byte, myHostname string, tlsCfg *tls.Config) error {
	// Connect to port 25 (IPv4 only)
	addr := host + ":25"
	conn, err := net.DialTimeout("tcp4", addr, 30*time.Second)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	// Read greeting
	reply, err := readReply(conn)
	if err != nil {
		return fmt.Errorf("reading greeting from %s: %w", host, err)
	}
	if !strings.HasPrefix(reply, "220") {
		return fmt.Errorf("unexpected greeting from %s: %s", host, reply)
	}

	// EHLO
	if err := sendCmd(conn, fmt.Sprintf("EHLO %s", myHostname)); err != nil {
		return err
	}
	ehloReply, err := readReply(conn)
	if err != nil {
		return fmt.Errorf("EHLO reply from %s: %w", host, err)
	}
	if !strings.HasPrefix(ehloReply, "250") {
		return fmt.Errorf("EHLO rejected by %s: %s", host, ehloReply)
	}

	// Try STARTTLS if supported
	if strings.Contains(ehloReply, "STARTTLS") && tlsCfg != nil {
		if err := sendCmd(conn, "STARTTLS"); err == nil {
			startTLSReply, err := readReply(conn)
			if err == nil && strings.HasPrefix(startTLSReply, "220") {
				clientTLS := tls.Client(conn, &tls.Config{
					ServerName:         host,
					InsecureSkipVerify: false,
					MinVersion:         tls.VersionTLS12,
				})
				if err := clientTLS.Handshake(); err != nil {
					log.Printf("[smtp] STARTTLS handshake with %s failed: %v (continuing without TLS)", host, err)
				} else {
					conn = clientTLS
					// Re-EHLO after STARTTLS
					if err := sendCmd(conn, fmt.Sprintf("EHLO %s", myHostname)); err == nil {
						readReply(conn) // Consume EHLO reply
					}
				}
			}
		}
	}

	// MAIL FROM (with DSN parameters)
	if err := sendCmd(conn, fmt.Sprintf("MAIL FROM:<%s> RET=FULL NOTIFY=FAILURE", from)); err != nil {
		return err
	}
	mailReply, err := readReply(conn)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(mailReply, "250") {
		return fmt.Errorf("MAIL FROM rejected by %s: %s", host, mailReply)
	}

	// RCPT TO
	if err := sendCmd(conn, fmt.Sprintf("RCPT TO:<%s>", to)); err != nil {
		return err
	}
	rcptReply, err := readReply(conn)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(rcptReply, "250") {
		return fmt.Errorf("RCPT TO rejected by %s: %s", host, rcptReply)
	}

	// DATA
	if err := sendCmd(conn, "DATA"); err != nil {
		return err
	}
	dataReply, err := readReply(conn)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(dataReply, "354") {
		return fmt.Errorf("DATA rejected by %s: %s", host, dataReply)
	}

	// Send message body
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("writing message to %s: %w", host, err)
	}
	// End with CRLF.CRLF
	if _, err := conn.Write([]byte("\r\n.\r\n")); err != nil {
		return fmt.Errorf("writing end-of-data to %s: %w", host, err)
	}

	finalReply, err := readReply(conn)
	if err != nil {
		return fmt.Errorf("reading final reply from %s: %w", host, err)
	}
	if !strings.HasPrefix(finalReply, "250") {
		return fmt.Errorf("message rejected by %s: %s", host, finalReply)
	}

	// QUIT
	sendCmd(conn, "QUIT")
	readReply(conn) // Best effort

	log.Printf("[smtp] delivered to %s via %s", to, host)
	return nil
}

func sendCmd(conn net.Conn, cmd string) error {
	_, err := fmt.Fprintf(conn, "%s\r\n", cmd)
	return err
}

func readReply(conn net.Conn) (string, error) {
	buf := make([]byte, 4096)
	var reply strings.Builder

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			reply.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return reply.String(), err
		}
		// Check if we have a complete reply (line ending without continuation)
		lines := strings.Split(reply.String(), "\n")
		lastLine := strings.TrimRight(lines[len(lines)-1], "\r\n ")
		if lastLine == "" && len(lines) > 1 {
			lastLine = strings.TrimRight(lines[len(lines)-2], "\r\n ")
		}
		if len(lastLine) >= 4 && lastLine[3] == ' ' {
			break
		}
	}

	return strings.TrimSpace(reply.String()), nil
}
