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
	"gomail/mta_sts"
	"gomail/store"
)

// SendMail delivers a message to a remote SMTP server via MX lookup.
// This is used by the delivery worker for outbound messages.
// DSN parameters (dsnNotify, dsnRet, dsnEnvID) are optional and can be empty.
// requireTLS: if true, fails delivery if TLS cannot be established; if false, uses opportunistic TLS
// network: "tcp" (both IPv4 and IPv6), "tcp4" (IPv4 only), "tcp6" (IPv6 only)
// db: database for recording TLS failures (optional, can be nil)
func SendMail(from, to string, msg []byte, hostname string, tlsCfg *tls.Config, requireTLS bool, dsnNotify, dsnRet, dsnEnvID, network string, db *store.DB) error {
	// Extract recipient domain
	parts := strings.SplitN(to, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid recipient address: %s", to)
	}
	domain := parts[1]

	// Fetch MTA-STS policy for recipient domain
	policy := mta_sts.FetchPolicy(domain)
	if policy != nil {
		log.Printf("[mta-sts] policy mode for %s: %s", domain, policy.Mode)
	}

	// MX lookup
	mxRecords, err := godns.LookupMX(domain)
	if err != nil {
		return fmt.Errorf("MX lookup for %s: %w", domain, err)
	}

	// Try each MX in preference order
	var lastErr error
	for _, mx := range mxRecords {
		// Check MTA-STS policy: validate MX host is in policy if policy exists
		if policy != nil && policy.Mode != "none" {
			// Check if this MX host is allowed by the policy
			hostAllowed := false
			for _, policyMX := range policy.MXHosts {
				if strings.EqualFold(mx.Host, policyMX) {
					hostAllowed = true
					break
				}
			}

			// Enforce TLS requirements based on policy mode
			if policy.Mode == "enforce" {
				// Enforce mode: skip hosts not in policy and require TLS
				if !hostAllowed {
					log.Printf("[mta-sts] MX host %s not in policy for %s, skipping", mx.Host, domain)
					continue
				}
				err := deliverToHost(mx.Host, from, to, msg, hostname, tlsCfg, true, dsnNotify, dsnRet, dsnEnvID, network, db, domain)
				if err == nil {
					return nil // Success
				}
				lastErr = err
				log.Printf("[mta-sts] ENFORCE delivery to %s failed: %v, trying next MX", mx.Host, err)
			} else if policy.Mode == "testing" {
				// Testing mode: log violations but allow delivery (even if host not in policy)
				if !hostAllowed {
					log.Printf("[mta-sts] TESTING: MX host %s not in policy for %s, but attempting anyway", mx.Host, domain)
				}
				err := deliverToHost(mx.Host, from, to, msg, hostname, tlsCfg, false, dsnNotify, dsnRet, dsnEnvID, network, db, domain)
				if err == nil {
					log.Printf("[mta-sts] TESTING delivery to %s succeeded", mx.Host)
					return nil
				}
				lastErr = err
				log.Printf("[mta-sts] TESTING violation for %s: %v", mx.Host, err)
			}
		} else {
			// No policy or mode=none: use normal delivery with original requireTLS setting
			err := deliverToHost(mx.Host, from, to, msg, hostname, tlsCfg, requireTLS, dsnNotify, dsnRet, dsnEnvID, network, db, domain)
			if err == nil {
				return nil // Success
			}
			lastErr = err
			log.Printf("[smtp] delivery to %s failed: %v, trying next MX", mx.Host, err)
		}
	}

	return fmt.Errorf("all MX hosts failed for %s: %w", domain, lastErr)
}

// deliverToHost connects to a specific SMTP host and delivers the message.
// requireTLS: if true, fails delivery if TLS cannot be established; if false, uses opportunistic TLS
// network: "tcp" (both IPv4 and IPv6), "tcp4" (IPv4 only), "tcp6" (IPv6 only)
// db: database for recording TLS failures (optional, can be nil)
// domain: recipient domain for TLS failure reporting (optional, used only if db != nil)
func deliverToHost(host, from, to string, msg []byte, myHostname string, tlsCfg *tls.Config, requireTLS bool, dsnNotify, dsnRet, dsnEnvID, network string, db *store.DB, domain string) error {
	// Connect to port 25
	addr := host + ":25"
	conn, err := net.DialTimeout(network, addr, 30*time.Second)
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

	// Check if server supports DSN (Delivery Status Notifications) and SMTPUTF8
	supportsDSN := strings.Contains(ehloReply, "DSN")
	supportsUTF8 := strings.Contains(ehloReply, "SMTPUTF8")

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
					// Record TLS failure for TLS-RPT reporting
					if db != nil && domain != "" {
						failureReason := "certificate-not-trusted"
						if strings.Contains(err.Error(), "certificate") {
							if strings.Contains(err.Error(), "expired") {
								failureReason = "certificate-expired"
							} else if strings.Contains(err.Error(), "verify") {
								failureReason = "certificate-not-trusted"
							} else {
								failureReason = "certificate-host-mismatch"
							}
						}
						clientIP := "unknown"
						if conn.LocalAddr() != nil {
							clientIP = strings.Split(conn.LocalAddr().String(), ":")[0]
						}
						_ = db.RecordTLSFailure(domain, failureReason, clientIP, host, strings.Split(addr, ":")[0])
					}

					if requireTLS {
						return fmt.Errorf("TLS required but STARTTLS handshake with %s failed: %w", host, err)
					}
					log.Printf("[smtp] STARTTLS handshake with %s failed: %v (continuing with opportunistic TLS disabled)", host, err)
				} else {
					conn = clientTLS
					// Re-EHLO after STARTTLS and update DSN/UTF8 support flags
					if err := sendCmd(conn, fmt.Sprintf("EHLO %s", myHostname)); err == nil {
						postTLSEhlo, _ := readReply(conn)
						supportsDSN = strings.Contains(postTLSEhlo, "DSN")
						supportsUTF8 = strings.Contains(postTLSEhlo, "SMTPUTF8")
					}
				}
			}
		}
	} else if requireTLS && !strings.Contains(ehloReply, "STARTTLS") {
		// TLS required but server doesn't support STARTTLS
		if db != nil && domain != "" {
			clientIP := "unknown"
			if conn.LocalAddr() != nil {
				clientIP = strings.Split(conn.LocalAddr().String(), ":")[0]
			}
			_ = db.RecordTLSFailure(domain, "connection-refused", clientIP, host, strings.Split(addr, ":")[0])
		}
		return fmt.Errorf("TLS required but %s does not support STARTTLS", host)
	}

	// MAIL FROM with SMTPUTF8 parameter (if supported)
	// Format: MAIL FROM:<addr> [SMTPUTF8] [RET=FULL|HDRS] [ENVID=<id>]
	// RFC 6531: Include SMTPUTF8 parameter when server supports it and sender is non-ASCII
	// Even if not advertised, try anyway - some servers support it without advertising
	mailFromCmd := fmt.Sprintf("MAIL FROM:<%s>", from)

	// Add SMTPUTF8 parameter if sender has non-ASCII characters and server supports it
	if hasNonASCII(from) && supportsUTF8 {
		mailFromCmd += " SMTPUTF8"
	}

	if supportsDSN {
		if dsnRet != "" {
			mailFromCmd += fmt.Sprintf(" RET=%s", dsnRet)
		}
		if dsnEnvID != "" {
			mailFromCmd += fmt.Sprintf(" ENVID=%s", dsnEnvID)
		}
	}

	if err := sendCmd(conn, mailFromCmd); err != nil {
		return err
	}
	log.Printf("[smtp] sent MAIL FROM command: %s (smtputf8=%v, nonascii=%v)", mailFromCmd, supportsUTF8, hasNonASCII(from))
	mailReply, err := readReply(conn)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(mailReply, "250") {
		return fmt.Errorf("MAIL FROM rejected by %s: %s", host, mailReply)
	}

	// RCPT TO with DSN and SMTPUTF8 parameters (RFC 3461, RFC 6531)
	// Format: RCPT TO:<addr> [SMTPUTF8] [NOTIFY=SUCCESS|FAILURE|DELAY|NEVER] [ORCPT=rfc822;<addr>]
	rcptToCmd := fmt.Sprintf("RCPT TO:<%s>", to)

	// Add SMTPUTF8 parameter if any recipient has non-ASCII characters and server supports it
	if hasNonASCII(to) && supportsUTF8 {
		rcptToCmd += " SMTPUTF8"
	}

	if supportsDSN && dsnNotify != "" {
		rcptToCmd += fmt.Sprintf(" NOTIFY=%s", dsnNotify)
	}

	if err := sendCmd(conn, rcptToCmd); err != nil {
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

// hasNonASCII checks if an email address contains non-ASCII (UTF-8) characters
func hasNonASCII(addr string) bool {
	for _, r := range addr {
		if r > 127 {
			return true
		}
	}
	return false
}
