package smtp

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	godns "gomail/dns"
	"gomail/mta_sts"
	"gomail/store"
	tlsconfig "gomail/tls"
)

// SendMail delivers a message to a remote SMTP server via MX lookup.
// This is used by the delivery worker for outbound messages.
// DSN parameters (dsnNotify, dsnRet, dsnEnvID) are optional and can be empty.
// requireTLS: if true, fails delivery if TLS cannot be established; if false, uses opportunistic TLS
// network: "tcp" (both IPv4 and IPv6), "tcp4" (IPv4 only), "tcp6" (IPv6 only)
// db: database for recording TLS failures (optional, can be nil)
func SendMail(from, to string, msg []byte, hostname string, tlsCfg *tls.Config, requireTLS bool, dsnNotify, dsnRet, dsnEnvID, network string, db *store.DB) error {
	// Extract sender domain (for DANE/TLS settings lookup)
	fromParts := strings.SplitN(from, "@", 2)
	senderDomain := ""
	if len(fromParts) == 2 {
		senderDomain = fromParts[1]
	}

	// Extract recipient domain
	parts := strings.SplitN(to, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid recipient address: %s", to)
	}
	recipientDomain := parts[1]

	// Fetch MTA-STS policy for recipient domain
	policy := mta_sts.FetchPolicy(recipientDomain)
	if policy != nil {
		log.Printf("[mta-sts] policy mode for %s: %s", recipientDomain, policy.Mode)
	}

	// MX lookup
	mxRecords, err := godns.LookupMX(recipientDomain)
	if err != nil {
		return fmt.Errorf("MX lookup for %s: %w", recipientDomain, err)
	}

	// Try each MX in preference order
	var lastErr error
	for _, mx := range mxRecords {
		// Check MTA-STS policy: validate MX host is in policy if policy exists
		if policy != nil && policy.Mode != "none" {
			// Check if this MX host is allowed by the policy
			hostAllowed := false
			for _, policyMX := range policy.MXHosts {
				if matchSTSMX(mx.Host, policyMX) {
					hostAllowed = true
					break
				}
			}

			// Enforce TLS requirements based on policy mode
			if policy.Mode == "enforce" {
				// Enforce mode: skip hosts not in policy and require TLS
				if !hostAllowed {
					log.Printf("[mta-sts] MX host %s not in policy for %s, skipping", mx.Host, recipientDomain)
					continue
				}
				err := deliverToHost(mx.Host, from, to, msg, hostname, tlsCfg, true, dsnNotify, dsnRet, dsnEnvID, network, db, recipientDomain, senderDomain)
				if err == nil {
					return nil // Success
				}
				lastErr = err
				log.Printf("[mta-sts] ENFORCE delivery to %s failed: %v, trying next MX", mx.Host, err)
			} else if policy.Mode == "testing" {
				// Testing mode: log violations but allow delivery (even if host not in policy)
				if !hostAllowed {
					log.Printf("[mta-sts] TESTING: MX host %s not in policy for %s, but attempting anyway", mx.Host, recipientDomain)
				}
				err := deliverToHost(mx.Host, from, to, msg, hostname, tlsCfg, false, dsnNotify, dsnRet, dsnEnvID, network, db, recipientDomain, senderDomain)
				if err == nil {
					log.Printf("[mta-sts] TESTING delivery to %s succeeded", mx.Host)
					return nil
				}
				lastErr = err
				log.Printf("[mta-sts] TESTING violation for %s: %v", mx.Host, err)
			}
		} else {
			// No policy or mode=none: use normal delivery with original requireTLS setting
			err := deliverToHost(mx.Host, from, to, msg, hostname, tlsCfg, requireTLS, dsnNotify, dsnRet, dsnEnvID, network, db, recipientDomain, senderDomain)
			if err == nil {
				return nil // Success
			}
			lastErr = err
			log.Printf("[smtp] delivery to %s failed: %v, trying next MX", mx.Host, err)
		}
	}

	return fmt.Errorf("all MX hosts failed for %s: %w", recipientDomain, lastErr)
}

// deliverToHost connects to a specific SMTP host and delivers the message.
// requireTLS: if true, fails delivery if TLS cannot be established; if false, uses opportunistic TLS
// network: "tcp" (both IPv4 and IPv6), "tcp4" (IPv4 only), "tcp6" (IPv6 only)
// db: database for recording TLS failures (optional, can be nil)
// recipientDomain: recipient domain for TLS failure reporting (optional, used only if db != nil)
// senderDomain: sender domain for DANE/TLS enforcement settings lookup
func deliverToHost(host, from, to string, msg []byte, myHostname string, tlsCfg *tls.Config, requireTLS bool, dsnNotify, dsnRet, dsnEnvID, network string, db *store.DB, recipientDomain, senderDomain string) error {
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
	supports8Bit := strings.Contains(ehloReply, "8BITMIME")
	daneEnforcement := "disabled"
	if db != nil && senderDomain != "" {
		if domainObj, lookupErr := db.GetDomainByName(senderDomain); lookupErr == nil && domainObj != nil && domainObj.DANEEnforcement != "" {
			daneEnforcement = domainObj.DANEEnforcement
		}
	}
	var daneLookup godns.TLSAResult
	if daneEnforcement != "disabled" {
		daneLookup, err = godns.LookupTLSA(host)
		if err != nil && daneEnforcement == "required" {
			return fmt.Errorf("DANE DNSSEC lookup required for %s: %w", host, err)
		}
		if err == nil && len(daneLookup.Records) == 0 && daneEnforcement == "required" {
			return fmt.Errorf("DANE required but no authenticated TLSA records exist for %s", host)
		}
	}

	// Try STARTTLS if supported
	if strings.Contains(ehloReply, "STARTTLS") && tlsCfg != nil {
		if err := sendCmd(conn, "STARTTLS"); err == nil {
			startTLSReply, err := readReply(conn)
			if err == nil && strings.HasPrefix(startTLSReply, "220") {
				clientConfig := tlsCfg.Clone()
				clientConfig.ServerName = host
				clientConfig.MinVersion = tls.VersionTLS12
				if daneLookup.Authenticated && len(daneLookup.Records) > 0 {
					clientConfig.InsecureSkipVerify = true // VerifyConnection below replaces default verification.
					clientConfig.VerifyConnection = func(state tls.ConnectionState) error {
						result, verifyErr := tlsconfig.VerifyDANECertificates(host, state.PeerCertificates, daneLookup.Records, clientConfig.RootCAs, time.Now())
						if verifyErr == nil && result.Matched {
							return nil
						}
						if daneEnforcement == "required" {
							if verifyErr != nil {
								return verifyErr
							}
							return fmt.Errorf("authenticated TLSA records did not match: %s", result.Details)
						}
						if len(state.PeerCertificates) == 0 {
							return fmt.Errorf("peer supplied no certificate")
						}
						pool := x509.NewCertPool()
						for _, cert := range state.PeerCertificates[1:] {
							pool.AddCert(cert)
						}
						_, pkixErr := state.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: host, Roots: clientConfig.RootCAs, Intermediates: pool})
						return pkixErr
					}
				}
				clientTLS := tls.Client(conn, clientConfig)
				if err := clientTLS.Handshake(); err != nil {
					// Record TLS failure for TLS-RPT reporting
					if db != nil && recipientDomain != "" {
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
						_ = db.RecordTLSFailure(recipientDomain, failureReason, clientIP, host, strings.Split(addr, ":")[0])
					}

					if requireTLS {
						return fmt.Errorf("TLS required but STARTTLS handshake with %s failed: %w", host, err)
					}
					log.Printf("[smtp] STARTTLS handshake with %s failed: %v (continuing with opportunistic TLS disabled)", host, err)
				} else {
					conn = clientTLS

					// DANE verification (RFC 6698): Check certificate against TLSA records
					// Only query DANE if enforcement is not disabled (avoid unnecessary DNS queries)
					if daneEnforcement != "disabled" {
						daneValid, daneDetails, daneErr := tlsconfig.VerifyDANE(host, clientTLS)
						clientIP := "unknown"
						if conn.LocalAddr() != nil {
							clientIP = strings.Split(conn.LocalAddr().String(), ":")[0]
						}

						if daneErr != nil {
							log.Printf("[dane] DANE verification lookup failed for %s: %v", host, daneErr)
							if daneEnforcement == "required" {
								return fmt.Errorf("DANE verification required but lookup failed for %s: %v", host, daneErr)
							} else if daneEnforcement == "optional" {
								log.Printf("[dane] DANE enforcement OPTIONAL: allowing delivery despite lookup failure")
							}
						} else if daneValid {
							log.Printf("[dane] DANE verification passed for %s: %s", host, daneDetails)
						} else if daneDetails == "no authenticated TLSA records" {
							// No TLSA records found
							if daneEnforcement == "required" {
								// Record DANE verification failure for TLS-RPT reporting
								if db != nil && recipientDomain != "" {
									_ = db.RecordTLSFailure(recipientDomain, "tlsa-missing", clientIP, host,
										strings.Split(addr, ":")[0])
									log.Printf("[dane] DANE enforcement REQUIRED: no TLSA records found, recorded failure for TLS-RPT")
								}
								return fmt.Errorf("DANE verification required but no TLSA records found for %s", host)
							} else if daneEnforcement == "optional" {
								// optional mode: TLSA not configured, use standard TLS
								log.Printf("[dane] no TLSA records for %s (DANE not configured, optional mode allows standard TLS)", host)
							}
						} else {
							// TLSA records exist but certificate doesn't match
							log.Printf("[dane] WARNING: DANE verification failed for %s: %s", host, daneDetails)

							// Handle DANE enforcement level
							if daneEnforcement == "required" {
								// Record DANE verification failure for TLS-RPT reporting
								if db != nil && recipientDomain != "" {
									_ = db.RecordTLSFailure(recipientDomain, "tlsa-invalid-certificate", clientIP, host,
										strings.Split(addr, ":")[0])
									log.Printf("[dane] DANE enforcement REQUIRED: recorded failure for TLS-RPT")
								}
								return fmt.Errorf("DANE verification required but failed for %s: %s", host, daneDetails)
							} else if daneEnforcement == "optional" {
								// Log warning but continue - allow fallback to standard TLS
								log.Printf("[dane] DANE enforcement OPTIONAL: allowing delivery despite DANE failure")
							}
						}
					} else {
						log.Printf("[dane] DANE verification disabled for %s (skipping TLSA queries)", host)
					}

					// Re-EHLO after STARTTLS and update DSN/UTF8 support flags
					if err := sendCmd(conn, fmt.Sprintf("EHLO %s", myHostname)); err == nil {
						postTLSEhlo, _ := readReply(conn)
						supportsDSN = strings.Contains(postTLSEhlo, "DSN")
						supportsUTF8 = strings.Contains(postTLSEhlo, "SMTPUTF8")
						supports8Bit = strings.Contains(postTLSEhlo, "8BITMIME")
					}
				}
			}
		}
	} else if requireTLS && !strings.Contains(ehloReply, "STARTTLS") {
		// TLS required but server doesn't support STARTTLS
		if db != nil && recipientDomain != "" {
			clientIP := "unknown"
			if conn.LocalAddr() != nil {
				clientIP = strings.Split(conn.LocalAddr().String(), ":")[0]
			}
			_ = db.RecordTLSFailure(recipientDomain, "connection-refused", clientIP, host, strings.Split(addr, ":")[0])
		}
		return fmt.Errorf("TLS required but %s does not support STARTTLS", host)
	}

	// MAIL FROM with SMTPUTF8 parameter (if supported)
	// Format: MAIL FROM:<addr> [SMTPUTF8] [RET=FULL|HDRS] [ENVID=<id>]
	// RFC 6531: Include SMTPUTF8 parameter when server supports it and sender is non-ASCII
	// Even if not advertised, try anyway - some servers support it without advertising
	mailFromCmd := fmt.Sprintf("MAIL FROM:<%s>", from)

	needsUTF8 := requiresSMTPUTF8(from, to, msg)
	if needsUTF8 && !supportsUTF8 {
		return fmt.Errorf("SMTPUTF8 required but not advertised by %s", host)
	}
	if needsUTF8 {
		mailFromCmd += " SMTPUTF8"
	}
	needs8Bit := has8Bit(msg)
	if needs8Bit && !supports8Bit {
		return fmt.Errorf("8BITMIME required but not advertised by %s", host)
	}
	if needs8Bit {
		mailFromCmd += " BODY=8BITMIME"
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

	// SMTPUTF8 is a MAIL FROM parameter, not an RCPT TO parameter.
	rcptToCmd := fmt.Sprintf("RCPT TO:<%s>", to)

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

	// Send message with RFC 5321 dot transparency and exactly one terminator.
	if err := writeSMTPData(conn, msg); err != nil {
		return fmt.Errorf("writing message to %s: %w", host, err)
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

func matchSTSMX(host, pattern string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	if !strings.HasPrefix(pattern, "*.") {
		return host == pattern
	}
	suffix := pattern[1:]
	prefix := strings.TrimSuffix(host, suffix)
	return strings.HasSuffix(host, suffix) && prefix != "" && !strings.Contains(prefix, ".")
}

func has8Bit(data []byte) bool {
	for _, b := range data {
		if b >= 0x80 {
			return true
		}
	}
	return false
}

func requiresSMTPUTF8(from, to string, msg []byte) bool {
	if hasNonASCII(from) || hasNonASCII(to) {
		return true
	}
	end := bytes.Index(msg, []byte("\r\n\r\n"))
	if end < 0 {
		end = bytes.Index(msg, []byte("\n\n"))
	}
	if end < 0 {
		end = len(msg)
	}
	return has8Bit(msg[:end])
}

func writeSMTPData(w io.Writer, msg []byte) error {
	data := bytes.ReplaceAll(msg, []byte("\r\n"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
	lines := bytes.Split(data, []byte("\n"))
	for i, line := range lines {
		if len(line) > 0 && line[0] == '.' {
			if _, err := w.Write([]byte{'.'}); err != nil {
				return err
			}
		}
		if _, err := w.Write(line); err != nil {
			return err
		}
		if i < len(lines)-1 {
			if _, err := w.Write([]byte("\r\n")); err != nil {
				return err
			}
		}
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		if _, err := w.Write([]byte("\r\n")); err != nil {
			return err
		}
	}
	_, err := w.Write([]byte(".\r\n"))
	return err
}
