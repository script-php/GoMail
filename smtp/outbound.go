package smtp

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	godns "gomail/dns"
	"gomail/metrics"
	"gomail/mta_sts"
	"gomail/store"
	tlsconfig "gomail/tls"
)

var errMissingSMTPUTF8 = errors.New("SMTPUTF8 not advertised")
var errMissing8BITMIME = errors.New("8BITMIME not advertised")
var errInvalidQueuedMessage = errors.New("invalid queued message")

// ErrDeliveryOutcomeUnknown means DATA may have been accepted, but its final
// reply was not received. Retrying automatically could duplicate the message.
var ErrDeliveryOutcomeUnknown = errors.New("remote delivery outcome unknown")

type replyFailure struct {
	context string
	reply   string
}

func (e *replyFailure) Error() string { return e.context + ": " + e.reply }

// SMTPFailureCode reports only actual SMTP replies or locally generated
// permanent address/format failures, never numbers found in HTTP/DNS errors.
func SMTPFailureCode(err error) int {
	var reply *replyFailure
	if errors.As(err, &reply) {
		code := smtpReplyCode(reply.reply)
		if len(code) == 3 && code[0] >= '4' && code[0] <= '5' {
			return int(code[0]-'0')*100 + int(code[1]-'0')*10 + int(code[2]-'0')
		}
	}
	if errors.Is(err, godns.ErrNullMX) {
		return 556
	}
	if errors.Is(err, godns.ErrNoMailRoute) {
		return 550
	}
	if errors.Is(err, errInvalidQueuedMessage) || isMissingMessageExtension(err) {
		return 554
	}
	return 0
}

// A delivery attempt is retryable if any candidate MX failed transiently.
// The last MX's permanent reply must not hide a retryable earlier attempt.
func preferredMXFailure(previous, current error) error {
	if previous == nil || !isPermanentMXFailure(previous) {
		if previous != nil {
			return previous
		}
		return current
	}
	if !isPermanentMXFailure(current) {
		return current
	}
	return previous
}

func isPermanentMXFailure(err error) bool {
	code := SMTPFailureCode(err)
	return code >= 500 && code < 600
}

func isMissingMessageExtension(err error) bool {
	return errors.Is(err, errMissingSMTPUTF8) || errors.Is(err, errMissing8BITMIME)
}

// SendMail delivers a message to a remote SMTP server via MX lookup.
// This is used by the delivery worker for outbound messages.
// DSN parameters (dsnNotify, dsnRet, dsnEnvID) are optional and can be empty.
func transportTLSRequired(requireTLS bool, daneEnforcement string) bool {
	return requireTLS || daneEnforcement == "required"
}

// A secure usable TLSA RRset commits the peer to authenticated TLS; a secure
// nonempty but unusable RRset commits it to encryption only. Insecure DNSSEC
// results are an ordinary absence of DANE, whereas lookup failures are not.
func daneTransportPolicy(enforcement string, result godns.TLSAResult, lookupErr error) (requireTLS, authenticate bool, err error) {
	if enforcement == "disabled" {
		return false, false, nil
	}
	if lookupErr != nil {
		if enforcement != "required" && errors.Is(lookupErr, godns.ErrDNSSECInsecure) && !result.Authenticated {
			return false, false, nil
		}
		return false, false, fmt.Errorf("TLSA lookup failed: %w", lookupErr)
	}
	if result.Authenticated && len(result.Records) > 0 {
		return true, true, nil
	}
	if result.Authenticated && result.UnusableRecords && enforcement != "required" {
		return true, false, nil
	}
	if enforcement == "required" {
		return false, false, fmt.Errorf("DANE required but no usable authenticated TLSA records exist")
	}
	return false, false, nil
}

// requireTLS: if true, fails delivery if TLS cannot be established; if false, uses opportunistic TLS
// network: "tcp" (both IPv4 and IPv6), "tcp4" (IPv4 only), "tcp6" (IPv6 only)
// db: database for recording TLS failures (optional, can be nil)
func SendMail(from, to string, msg []byte, hostname string, tlsCfg *tls.Config, requireTLS bool, dsnNotify, dsnRet, dsnEnvID, network string, db *store.DB, policyDomain ...string) error {
	if strings.ContainsAny(from, "\r\n<>") || strings.ContainsAny(to, "\r\n<>") {
		return fmt.Errorf("invalid envelope address")
	}
	if err := validateSMTPDataLines(msg); err != nil {
		return fmt.Errorf("554 5.6.0 invalid queued message: %w: %v", errInvalidQueuedMessage, err)
	}
	// Extract sender domain (for DANE/TLS settings lookup)
	fromParts := strings.SplitN(from, "@", 2)
	senderDomain := ""
	if len(fromParts) == 2 {
		senderDomain = fromParts[1]
	}
	if from == "" && len(policyDomain) != 0 {
		senderDomain = policyDomain[0]
	}
	originalRecipient := to
	if len(policyDomain) > 1 && policyDomain[1] != "" {
		originalRecipient = policyDomain[1]
	}

	// Extract recipient domain
	parts := strings.SplitN(to, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid recipient address: %s", to)
	}
	recipientDomain := parts[1]

	// Mandatory DANE authenticates the MX path as well as the TLSA RRset.
	// A TLSA match for an attacker-chosen, insecure MX does not authenticate
	// delivery to the intended recipient domain.
	daneEnforcement := "disabled"
	if db != nil && senderDomain != "" {
		domainObj, lookupErr := db.GetDomainByName(senderDomain)
		if lookupErr != nil {
			return fmt.Errorf("loading sender transport policy: %w", lookupErr)
		}
		if domainObj == nil || !domainObj.IsActive {
			return fmt.Errorf("sender domain is missing or inactive")
		}
		daneEnforcement = domainObj.DANEEnforcement
		requireTLS = requireTLS || domainObj.RequireTLS
	}
	// Fetch after validating the local sender policy, but before any MX or
	// network delivery. A cache read failure must not downgrade enforcement.
	policy, err := mta_sts.FetchPolicyWithStore(recipientDomain, db)
	if err != nil {
		return fmt.Errorf("MTA-STS policy for %s: %w", recipientDomain, err)
	}
	if policy != nil {
		log.Printf("[mta-sts] policy mode for %s: %s", recipientDomain, policy.Mode)
	}
	requiredDANE := daneEnforcement == "required"
	var mxRecords []godns.MXRecord
	if requiredDANE {
		mxRecords, err = godns.LookupMXAuthenticated(recipientDomain)
	} else {
		mxRecords, err = godns.LookupMX(recipientDomain)
	}
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
					recordTLSResults(db, tlsReportEvents(recipientDomain, mx.Host, nil, policy, godns.TLSAResult{}), false,
						"validation-failure", "MX hostname is not permitted by the MTA-STS policy")
					continue
				}
				err := deliverToHost(mx.Host, from, to, msg, hostname, tlsCfg, true, dsnNotify, dsnRet, dsnEnvID, network, db, recipientDomain, daneEnforcement, policy, originalRecipient)
				if err == nil {
					return nil // Success
				}
				if errors.Is(err, ErrDeliveryOutcomeUnknown) {
					return err
				}
				lastErr = preferredMXFailure(lastErr, err)
				log.Printf("[mta-sts] ENFORCE delivery to %s failed: %v, trying next MX", mx.Host, err)
			} else if policy.Mode == "testing" {
				// Testing mode: log violations but allow delivery (even if host not in policy)
				if !hostAllowed {
					log.Printf("[mta-sts] TESTING: MX host %s not in policy for %s, but attempting anyway", mx.Host, recipientDomain)
				}
				err := deliverToHost(mx.Host, from, to, msg, hostname, tlsCfg, requireTLS, dsnNotify, dsnRet, dsnEnvID, network, db, recipientDomain, daneEnforcement, policy, originalRecipient)
				if err == nil {
					log.Printf("[mta-sts] TESTING delivery to %s succeeded", mx.Host)
					return nil
				}
				if errors.Is(err, ErrDeliveryOutcomeUnknown) {
					return err
				}
				lastErr = preferredMXFailure(lastErr, err)
				log.Printf("[mta-sts] TESTING violation for %s: %v", mx.Host, err)
			}
		} else {
			// No policy or mode=none: use normal delivery with original requireTLS setting
			err := deliverToHost(mx.Host, from, to, msg, hostname, tlsCfg, requireTLS, dsnNotify, dsnRet, dsnEnvID, network, db, recipientDomain, daneEnforcement, nil, originalRecipient)
			if err == nil {
				return nil // Success
			}
			if errors.Is(err, ErrDeliveryOutcomeUnknown) {
				return err
			}
			lastErr = preferredMXFailure(lastErr, err)
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
// daneEnforcement is resolved once before MX lookup; DB errors cannot downgrade it.
func deliverToHost(host, from, to string, msg []byte, myHostname string, tlsCfg *tls.Config, requireTLS bool, dsnNotify, dsnRet, dsnEnvID, network string, db *store.DB, recipientDomain, daneEnforcement string, stsPolicy *mta_sts.Policy, originalRecipients ...string) error {
	return deliverToHostAt(net.JoinHostPort(host, "25"), host, from, to, msg, myHostname, tlsCfg, requireTLS, dsnNotify, dsnRet, dsnEnvID, network, db, recipientDomain, daneEnforcement, stsPolicy, originalRecipients...)
}

// deliverToHostAt permits loopback interoperability tests without binding port 25.
func deliverToHostAt(addr, host, from, to string, msg []byte, myHostname string, tlsCfg *tls.Config, requireTLS bool, dsnNotify, dsnRet, dsnEnvID, network string, db *store.DB, recipientDomain, daneEnforcement string, stsPolicy *mta_sts.Policy, originalRecipients ...string) error {
	conn, err := net.DialTimeout(network, addr, 30*time.Second)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer conn.Close()

	// Read greeting
	reply, err := readReply(conn)
	if err != nil {
		return fmt.Errorf("reading greeting from %s: %w", host, err)
	}
	if !strings.HasPrefix(reply, "220") {
		return &replyFailure{fmt.Sprintf("unexpected greeting from %s", host), reply}
	}

	// Check if server supports DSN (Delivery Status Notifications) and SMTPUTF8
	capabilities, err := smtpGreetingCapabilities(conn, myHostname)
	if err != nil {
		return fmt.Errorf("SMTP greeting with %s: %w", host, err)
	}
	supportsDSN := capabilities["DSN"]
	supportsUTF8 := capabilities["SMTPUTF8"]
	supports8Bit := capabilities["8BITMIME"]
	var daneLookup godns.TLSAResult
	var daneLookupErr error
	if daneEnforcement != "disabled" {
		daneLookup, daneLookupErr = godns.LookupTLSAForMX(host)
		if daneLookupErr == nil && len(daneLookup.Records) > 0 {
			metrics.IncDANE("authenticated")
		} else if errors.Is(daneLookupErr, godns.ErrDNSSECInsecure) {
			metrics.IncDANE("insecure")
		} else if daneLookup.UnusableRecords {
			metrics.IncDANE("malformed")
		} else if errors.Is(daneLookupErr, godns.ErrNoTLSA) || daneLookupErr == nil {
			metrics.IncDANE("no_record")
		} else {
			metrics.IncDANE("lookup_error")
		}
	}
	daneRequireTLS, daneAuthenticate, policyErr := daneTransportPolicy(daneEnforcement, daneLookup, daneLookupErr)
	if policyErr != nil {
		recordTLSResults(db, tlsReportEvents(recipientDomain, host, conn, stsPolicy, daneLookup), false, "dnssec-invalid", policyErr.Error())
		return fmt.Errorf("DANE policy for %s: %w", host, policyErr)
	}
	effectiveRequireTLS := transportTLSRequired(requireTLS, daneEnforcement) || daneRequireTLS
	reportEvents := tlsReportEvents(recipientDomain, host, conn, stsPolicy, daneLookup)
	tlsEstablished := false
	var daneVerifyResult tlsconfig.DANEResult
	var daneVerifyErr error
	var stsVerifyErr error

	// Try STARTTLS if supported
	if capabilities["STARTTLS"] && tlsCfg != nil {
		if err := sendCmd(conn, "STARTTLS"); err != nil {
			return fmt.Errorf("sending STARTTLS to %s: %w", host, err)
		} else {
			startTLSReply, err := readReply(conn)
			if err != nil {
				return fmt.Errorf("reading STARTTLS reply from %s: %w", host, err)
			}
			if strings.HasPrefix(startTLSReply, "220") {
				clientConfig := tlsCfg.Clone()
				tlsaHost := host
				if daneLookup.Authenticated && (len(daneLookup.Records) > 0 || daneLookup.UnusableRecords) {
					tlsaHost = tlsaBaseDomain(host, daneLookup.Name)
				}
				clientConfig.ServerName = tlsaHost
				clientConfig.MinVersion = outboundMinTLSVersion(clientConfig.MinVersion)
				stsMode := ""
				if stsPolicy != nil {
					stsMode = stsPolicy.Mode
				}
				if daneAuthenticate {
					clientConfig.InsecureSkipVerify = true // VerifyConnection below replaces default verification.
					clientConfig.VerifyConnection = func(state tls.ConnectionState) error {
						if stsMode == "enforce" || stsMode == "testing" {
							stsVerifyErr = verifySTSCertificate(state.PeerCertificates, host, clientConfig.RootCAs)
						}
						var extraNames []string
						if daneEnforcement == "required" {
							extraNames = append(extraNames, recipientDomain)
						}
						daneVerifyResult, daneVerifyErr = tlsconfig.VerifyDANECertificates(tlsaHost, state.PeerCertificates, daneLookup.Records, clientConfig.RootCAs, time.Now(), extraNames...)
						if daneVerifyErr == nil && daneVerifyResult.Matched {
							if stsMode == "enforce" {
								return stsVerifyErr
							}
							return nil
						}
						if daneVerifyErr != nil {
							return daneVerifyErr
						}
						return fmt.Errorf("authenticated TLSA records did not match: %s", daneVerifyResult.Details)
					}
				} else if daneLookup.UnusableRecords {
					// RFC 7672: secure, nonempty but unusable TLSA requires
					// encryption, not certificate authentication.
					if stsMode != "enforce" {
						clientConfig.InsecureSkipVerify = true
						if stsMode == "testing" {
							clientConfig.VerifyConnection = func(state tls.ConnectionState) error {
								stsVerifyErr = verifySTSCertificate(state.PeerCertificates, host, clientConfig.RootCAs)
								return nil
							}
						} else {
							clientConfig.VerifyConnection = nil
						}
					}
				} else if stsMode == "testing" {
					clientConfig.InsecureSkipVerify = true
					clientConfig.VerifyConnection = func(state tls.ConnectionState) error {
						stsVerifyErr = verifySTSCertificate(state.PeerCertificates, host, clientConfig.RootCAs)
						return nil
					}
				} else if !effectiveRequireTLS && stsMode != "enforce" {
					// Ordinary opportunistic SMTP encrypts the connection without
					// authenticating the peer. Never apply this to an enforced policy.
					clientConfig.InsecureSkipVerify = true
					clientConfig.VerifyConnection = nil
				}
				clientTLS := tls.Client(conn, clientConfig)
				if err := conn.SetDeadline(time.Now().Add(5 * time.Minute)); err != nil {
					return fmt.Errorf("setting STARTTLS deadline for %s: %w", host, err)
				}
				if err := clientTLS.Handshake(); err != nil {
					daneFailed := daneLookup.Authenticated && len(daneLookup.Records) > 0 && (daneVerifyErr != nil || !daneVerifyResult.Matched)
					if daneFailed {
						metrics.IncDANE("mismatch")
					}
					// Record TLS failure for TLS-RPT reporting
					if db != nil && recipientDomain != "" {
						failureReason := "certificate-not-trusted"
						if daneFailed {
							failureReason = "tlsa-invalid"
						} else if strings.Contains(err.Error(), "certificate") {
							if strings.Contains(err.Error(), "expired") {
								failureReason = "certificate-expired"
							} else if strings.Contains(err.Error(), "verify") {
								failureReason = "certificate-not-trusted"
							} else {
								failureReason = "certificate-host-mismatch"
							}
						}
						failureEvents := reportEvents
						if stsVerifyErr != nil && !daneFailed {
							failureEvents = filterTLSReportEvents(reportEvents, "sts")
						}
						recordTLSResults(db, failureEvents, false, failureReason, err.Error())
					}

					// After STARTTLS acceptance, the connection speaks TLS, not
					// plaintext SMTP. A later cleartext attempt needs a new socket.
					return fmt.Errorf("STARTTLS handshake with %s failed: %w", host, err)
				} else {
					conn = clientTLS
					tlsEstablished = true

					// Report the same authenticated RRset used by VerifyConnection. A second
					// lookup here could observe a different DNS rotation state.
					if daneEnforcement == "disabled" {
						log.Printf("[dane] DANE verification disabled for %s (skipping TLSA queries)", host)
					} else if errors.Is(daneLookupErr, godns.ErrDNSSECInsecure) {
						log.Printf("[dane] insecure TLSA response for %s; DANE authentication does not apply", host)
					} else if daneLookup.UnusableRecords {
						log.Printf("[dane] authenticated TLSA RRset for %s is unusable; TLS encryption enforced without DANE authentication", host)
					} else if len(daneLookup.Records) == 0 {
						log.Printf("[dane] no authenticated TLSA records for %s; using PKIX", host)
					} else if daneVerifyErr == nil && daneVerifyResult.Matched {
						metrics.IncDANE("matched")
						log.Printf("[dane] DANE verification passed for %s: %s", host, daneVerifyResult.Details)
					} else {
						metrics.IncDANE("mismatch")
						details := daneVerifyResult.Details
						if daneVerifyErr != nil {
							details = daneVerifyErr.Error()
						}
						log.Printf("[dane] WARNING: DANE verification failed for %s: %s", host, details)
						recordTLSResults(db, filterTLSReportEvents(reportEvents, "tlsa"), false, "tlsa-invalid", details)
						reportEvents = excludeTLSReportEvents(reportEvents, "tlsa")
					}
					if stsVerifyErr != nil {
						recordTLSResults(db, filterTLSReportEvents(reportEvents, "sts"), false, "certificate-not-trusted", stsVerifyErr.Error())
						reportEvents = excludeTLSReportEvents(reportEvents, "sts")
					}
					recordTLSResults(db, reportEvents, true, "", "")

					// Re-EHLO after STARTTLS and update DSN/UTF8 support flags
					if err := sendCmd(conn, fmt.Sprintf("EHLO %s", myHostname)); err != nil {
						return fmt.Errorf("sending post-STARTTLS EHLO to %s: %w", host, err)
					}
					postTLSEhlo, err := readReply(conn)
					if err != nil {
						return fmt.Errorf("reading post-STARTTLS EHLO from %s: %w", host, err)
					}
					if !strings.HasPrefix(postTLSEhlo, "250 ") && !strings.HasPrefix(postTLSEhlo, "250-") {
						return &replyFailure{fmt.Sprintf("post-STARTTLS EHLO rejected by %s", host), postTLSEhlo}
					}
					capabilities = ehloCapabilities(postTLSEhlo)
					supportsDSN = capabilities["DSN"]
					supportsUTF8 = capabilities["SMTPUTF8"]
					supports8Bit = capabilities["8BITMIME"]
				}
			} else if effectiveRequireTLS {
				return &replyFailure{fmt.Sprintf("TLS required but STARTTLS was rejected by %s", host), startTLSReply}
			}
		}
	} else if !capabilities["STARTTLS"] {
		recordTLSResults(db, reportEvents, false, "starttls-not-supported", "STARTTLS was not advertised")
		if effectiveRequireTLS {
			return fmt.Errorf("TLS required but %s does not support STARTTLS", host)
		}
	}
	if effectiveRequireTLS && !tlsEstablished {
		return fmt.Errorf("TLS required but a secure STARTTLS session could not be established with %s", host)
	}

	// MAIL FROM with SMTPUTF8 parameter (if supported)
	// Format: MAIL FROM:<addr> [SMTPUTF8] [RET=FULL|HDRS] [ENVID=<id>]
	// RFC 6531: Include SMTPUTF8 parameter when server supports it and sender is non-ASCII
	// Even if not advertised, try anyway - some servers support it without advertising
	mailFromCmd := fmt.Sprintf("MAIL FROM:<%s>", from)

	needsUTF8, needs8Bit, formatErr := outboundFormatRequirements(from, to, msg, supportsUTF8, supports8Bit, host)
	if formatErr != nil {
		return formatErr
	}
	if needsUTF8 {
		mailFromCmd += " SMTPUTF8"
	}
	if needs8Bit {
		mailFromCmd += " BODY=8BITMIME"
	}

	if supportsDSN {
		if dsnRet != "" {
			mailFromCmd += fmt.Sprintf(" RET=%s", dsnRet)
		}
		if dsnEnvID != "" {
			mailFromCmd += fmt.Sprintf(" ENVID=%s", encodeXText(dsnEnvID))
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
		return &replyFailure{fmt.Sprintf("MAIL FROM rejected by %s", host), mailReply}
	}

	// SMTPUTF8 is a MAIL FROM parameter, not an RCPT TO parameter.
	rcptToCmd := recipientCommand(to, supportsDSN, supportsUTF8, dsnNotify, originalRecipients...)

	if err := sendCmd(conn, rcptToCmd); err != nil {
		return err
	}
	rcptReply, err := readReply(conn)
	if err != nil {
		return err
	}
	if code := smtpReplyCode(rcptReply); code != "250" && code != "251" {
		return &replyFailure{fmt.Sprintf("RCPT TO rejected by %s", host), rcptReply}
	}

	// DATA
	if err := sendCmd(conn, "DATA"); err != nil {
		return err
	}
	dataReply, err := readReplyWithTimeout(conn, 2*time.Minute)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(dataReply, "354") {
		return &replyFailure{fmt.Sprintf("DATA rejected by %s", host), dataReply}
	}

	// Send message with RFC 5321 dot transparency and exactly one terminator.
	if err := writeSMTPData(smtpDeadlineWriter{conn: conn, timeout: 3 * time.Minute}, msg); err != nil {
		return fmt.Errorf("writing message to %s: %w: %v", host, ErrDeliveryOutcomeUnknown, err)
	}

	finalReply, err := readReplyWithTimeout(conn, 10*time.Minute)
	if err != nil {
		return fmt.Errorf("reading final reply from %s: %w: %v", host, ErrDeliveryOutcomeUnknown, err)
	}
	if !strings.HasPrefix(finalReply, "250") {
		return &replyFailure{fmt.Sprintf("message rejected by %s", host), finalReply}
	}

	// QUIT
	_ = sendCmdWithTimeout(conn, "QUIT", 10*time.Second)
	_, _ = readReplyWithTimeout(conn, 10*time.Second) // Best effort

	log.Printf("[smtp] delivered to %s via %s", to, host)
	return nil
}

func outboundMinTLSVersion(configured uint16) uint16 {
	if configured > tls.VersionTLS12 {
		return configured
	}
	return tls.VersionTLS12
}

func tlsaBaseDomain(mxHost, owner string) string {
	const prefix = "_25._tcp."
	if strings.HasPrefix(strings.ToLower(owner), prefix) {
		base := strings.TrimSuffix(owner[len(prefix):], ".")
		if base != "" {
			return base
		}
	}
	return strings.TrimSuffix(mxHost, ".")
}

func recipientCommand(to string, supportsDSN, supportsUTF8 bool, dsnNotify string, originalRecipients ...string) string {
	command := fmt.Sprintf("RCPT TO:<%s>", to)
	if !supportsDSN {
		return command
	}
	if dsnNotify != "" {
		command += " NOTIFY=" + dsnNotify
	}
	if len(originalRecipients) > 0 && originalRecipients[0] != "" {
		command += " ORCPT=" + originalRecipientParameter(originalRecipients[0], supportsUTF8)
	} else if dsnNotify != "" {
		command += " ORCPT=" + originalRecipientParameter(to, supportsUTF8)
	}
	return command
}

func outboundFormatRequirements(from, to string, msg []byte, supportsUTF8, supports8Bit bool, host string) (bool, bool, error) {
	needsUTF8 := requiresSMTPUTF8(from, to, msg)
	if needsUTF8 && !supportsUTF8 {
		return false, false, fmt.Errorf("554 5.6.0 SMTPUTF8 required but not advertised by %s: %w", host, errMissingSMTPUTF8)
	}
	needs8Bit := has8Bit(msg)
	if needs8Bit && !supports8Bit {
		return false, false, fmt.Errorf("554 5.6.3 8BITMIME required but not advertised by %s: %w", host, errMissing8BITMIME)
	}
	return needsUTF8, needs8Bit, nil
}

// smtpGreetingCapabilities falls back to legacy HELO only when EHLO is not
// recognized. An empty capability set then prevents use of STARTTLS, DSN,
// SMTPUTF8 and 8BITMIME on that connection.
func smtpGreetingCapabilities(conn net.Conn, hostname string) (map[string]bool, error) {
	if err := sendCmd(conn, "EHLO "+hostname); err != nil {
		return nil, err
	}
	reply, err := readReply(conn)
	if err != nil {
		return nil, fmt.Errorf("reading EHLO reply: %w", err)
	}
	if smtpReplyCode(reply) == "250" {
		return ehloCapabilities(reply), nil
	}
	if code := smtpReplyCode(reply); code != "500" && code != "502" {
		return nil, &replyFailure{"EHLO rejected", reply}
	}
	if err := sendCmd(conn, "HELO "+hostname); err != nil {
		return nil, err
	}
	heloReply, err := readReply(conn)
	if err != nil {
		return nil, fmt.Errorf("reading HELO reply: %w", err)
	}
	if smtpReplyCode(heloReply) != "250" {
		return nil, &replyFailure{"HELO rejected", heloReply}
	}
	return map[string]bool{}, nil
}

func sendCmd(conn net.Conn, cmd string) error {
	return sendCmdWithTimeout(conn, cmd, 5*time.Minute)
}

func sendCmdWithTimeout(conn net.Conn, cmd string, timeout time.Duration) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	return writeSMTPChunk(conn, []byte(cmd+"\r\n"))
}

type smtpDeadlineWriter struct {
	conn    net.Conn
	timeout time.Duration
}

func (w smtpDeadlineWriter) Write(data []byte) (int, error) {
	if err := w.conn.SetWriteDeadline(time.Now().Add(w.timeout)); err != nil {
		return 0, err
	}
	return w.conn.Write(data)
}

// readReply validates the reply framing, so its first three bytes are the
// status code even when a successful reply spans multiple lines.
func smtpReplyCode(reply string) string {
	if len(reply) < 3 {
		return ""
	}
	return reply[:3]
}

func readReply(conn net.Conn) (string, error) {
	return readReplyWithTimeout(conn, 5*time.Minute)
}

func readReplyWithTimeout(conn net.Conn, timeout time.Duration) (string, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	const maxLine = 4096
	const maxReply = 65536
	var reply strings.Builder
	var line []byte
	var firstCode string
	var one [1]byte
	for reply.Len()+len(line) < maxReply {
		// Do not buffer ahead: the caller may issue another command on this
		// connection after consuming exactly one SMTP reply.
		if _, err := io.ReadFull(conn, one[:]); err != nil {
			return "", fmt.Errorf("incomplete SMTP reply: %w", err)
		}
		line = append(line, one[0])
		if len(line) > maxLine {
			return "", fmt.Errorf("SMTP reply line exceeds %d bytes", maxLine)
		}
		if one[0] != '\n' {
			continue
		}
		if len(line) < 5 || line[len(line)-2] != '\r' ||
			line[0] < '0' || line[0] > '9' ||
			line[1] < '0' || line[1] > '9' ||
			line[2] < '0' || line[2] > '9' ||
			(len(line) != 5 && (line[3] != ' ' && line[3] != '-')) {
			return "", fmt.Errorf("malformed SMTP reply line")
		}
		code := string(line[:3])
		if firstCode == "" {
			firstCode = code
		} else if code != firstCode {
			return "", fmt.Errorf("inconsistent SMTP reply code")
		}
		reply.Write(line)
		if len(line) == 5 || line[3] == ' ' {
			return strings.TrimSuffix(reply.String(), "\r\n"), nil
		}
		line = line[:0]
	}
	return "", fmt.Errorf("SMTP reply exceeds %d bytes", maxReply)
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

// The first EHLO line is the server greeting, not a capability. Extension
// keywords occupy the first token on subsequent 250-/250 lines (RFC 5321).
func ehloCapabilities(reply string) map[string]bool {
	capabilities := make(map[string]bool)
	lines := strings.Split(reply, "\r\n")
	for _, line := range lines[1:] {
		if len(line) < 5 || !strings.HasPrefix(line, "250") || (line[3] != '-' && line[3] != ' ') {
			continue
		}
		fields := strings.Fields(line[4:])
		if len(fields) > 0 {
			capabilities[strings.ToUpper(fields[0])] = true
		}
	}
	return capabilities
}

func originalRecipientParameter(address string, supportsUTF8 bool) string {
	if !hasNonASCII(address) {
		return "rfc822;" + encodeXText(address)
	}
	// RFC 6533's utf-8-addr-unitext form keeps Unicode octets on an SMTPUTF8
	// connection while escaping ASCII characters forbidden in ORCPT.
	if supportsUTF8 {
		var value strings.Builder
		for _, r := range address {
			if r <= 32 || r == 127 || r == '\\' || r == '+' || r == '=' {
				fmt.Fprintf(&value, "\\x{%X}", r)
			} else {
				value.WriteRune(r)
			}
		}
		return "utf-8;" + value.String()
	}
	// RFC 6533's 7-bit-safe utf-8-addr-xtext form for legacy DSN peers.
	var value strings.Builder
	for _, r := range address {
		if r > 126 || r <= 32 || r == 127 || r == '\\' || r == '+' || r == '=' {
			fmt.Fprintf(&value, "\\x{%X}", r)
		} else {
			value.WriteRune(r)
		}
	}
	return "utf-8;" + value.String()
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

func verifySTSCertificate(certs []*x509.Certificate, host string, roots *x509.CertPool) error {
	if len(certs) == 0 {
		return fmt.Errorf("SMTP peer sent no certificate")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: intermediates, CurrentTime: time.Now()})
	return err
}

func tlsReportEvents(recipientDomain, host string, conn net.Conn, stsPolicy *mta_sts.Policy, dane godns.TLSAResult) []store.TLSEvent {
	base := store.TLSEvent{RecipientDomain: recipientDomain, PolicyDomain: recipientDomain,
		ReceivingMXHostname: strings.TrimSuffix(host, ".")}
	if conn != nil {
		base.SendingMTAIP = addressIP(conn.LocalAddr())
		base.ReceivingIP = addressIP(conn.RemoteAddr())
	}
	var events []store.TLSEvent
	if stsPolicy != nil && stsPolicy.Mode != "none" {
		event := base
		event.PolicyType = "sts"
		event.MXHostPattern = append([]string(nil), stsPolicy.MXHosts...)
		event.PolicyString = []string{fmt.Sprintf("version: %s", stsPolicy.Version), fmt.Sprintf("mode: %s", stsPolicy.Mode)}
		for _, mx := range stsPolicy.MXHosts {
			event.PolicyString = append(event.PolicyString, "mx: "+mx)
		}
		event.PolicyString = append(event.PolicyString, fmt.Sprintf("max_age: %d", stsPolicy.MaxAge))
		events = append(events, event)
	}
	if dane.Authenticated && len(dane.Records) > 0 {
		event := base
		event.PolicyType = "tlsa"
		event.PolicyDomain = strings.TrimSuffix(host, ".")
		for _, record := range dane.Records {
			event.PolicyString = append(event.PolicyString, fmt.Sprintf("%d %d %d %s", record.Usage, record.Selector, record.MatchingType, record.CertData))
		}
		events = append(events, event)
	}
	if len(events) == 0 {
		base.PolicyType = "no-policy-found"
		events = append(events, base)
	}
	return events
}

func recordTLSResults(db *store.DB, events []store.TLSEvent, successful bool, resultType, reason string) {
	if db == nil {
		return
	}
	for _, event := range events {
		event.Successful = successful
		event.FailureReason = resultType
		event.FailureReasonCode = reason
		_ = db.RecordTLSEvent(event)
	}
}

func filterTLSReportEvents(events []store.TLSEvent, policyType string) []store.TLSEvent {
	var filtered []store.TLSEvent
	for _, event := range events {
		if event.PolicyType == policyType {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func excludeTLSReportEvents(events []store.TLSEvent, policyType string) []store.TLSEvent {
	var filtered []store.TLSEvent
	for _, event := range events {
		if event.PolicyType != policyType {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func addressIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return host
	}
	return addr.String()
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

func validateSMTPDataLines(msg []byte) error {
	for i, b := range msg {
		if b == '\r' && (i+1 >= len(msg) || msg[i+1] != '\n') || b == '\n' && (i == 0 || msg[i-1] != '\r') {
			return fmt.Errorf("bare CR or LF in signed message")
		}
	}
	lines := bytes.Split(msg, []byte("\r\n"))
	for _, line := range lines {
		wireLength := len(line) + 2 // RFC 5321 excludes the transparency dot.
		if wireLength > 1000 {
			return fmt.Errorf("SMTP DATA line exceeds 1000 octets")
		}
	}
	return nil
}

// ValidateSMTPDataLines checks the DATA framing accepted by outbound SMTP.
// Queue admission uses the same check so an unsendable message is not saved.
func ValidateSMTPDataLines(msg []byte) error { return validateSMTPDataLines(msg) }

func writeSMTPData(w io.Writer, msg []byte) error {
	if err := validateSMTPDataLines(msg); err != nil {
		return err
	}
	lines := bytes.Split(msg, []byte("\r\n"))
	for i, line := range lines {
		if len(line) > 0 && line[0] == '.' {
			if err := writeSMTPChunk(w, []byte{'.'}); err != nil {
				return err
			}
		}
		if err := writeSMTPChunk(w, line); err != nil {
			return err
		}
		if i < len(lines)-1 {
			if err := writeSMTPChunk(w, []byte("\r\n")); err != nil {
				return err
			}
		}
	}
	if !bytes.HasSuffix(msg, []byte("\r\n")) {
		if err := writeSMTPChunk(w, []byte("\r\n")); err != nil {
			return err
		}
	}
	return writeSMTPChunk(w, []byte(".\r\n"))
}

func writeSMTPChunk(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
