package reporting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DSNRequest represents DSN parameters from MAIL FROM or RCPT TO.
// RFC 3461 - SMTP Service Extension for Delivery Status Notifications
type DSNRequest struct {
	NotifyFlags   string // "SUCCESS", "FAILURE", "DELAY", "NEVER" (comma-separated)
	ReturnType    string // "FULL" or "HDRS"
	OrigRecipient string // Original recipient address (ORCPT)
	EnvID         string // Envelope ID
}

// DSNMessage represents a complete DSN report (both per-message and per-recipient info).
type DSNMessage struct {
	ReportingMTA      string     `json:"reporting_mta"`
	DSNGateway        string     `json:"dsn_gateway,omitempty"`
	ArrivalDate       time.Time  `json:"arrival_date"`
	MessageID         string     `json:"message_id"`
	OriginalRecipient string     `json:"original_recipient,omitempty"`
	FinalRecipient    string     `json:"final_recipient"`
	Action            string     `json:"action"`                    // delivered, failed, delayed
	Status            string     `json:"status"`                    // RFC 3463 status code (e.g., "5.1.1")
	DiagnosticCode    string     `json:"diagnostic_code,omitempty"` // RFC 3463 code
	LastAttemptDate   time.Time  `json:"last_attempt_date"`
	WillRetryUntil    *time.Time `json:"will_retry_until,omitempty"` // For delayed
	RemoteMTA         string     `json:"remote_mta,omitempty"`
	RemoteDiagnostic  string     `json:"remote_diagnostic,omitempty"`
}

// StatusCode represents RFC 3463 Enhanced Mail System Status Codes.
type StatusCode struct {
	Class   string // "2" (success), "4" (persistent temp failure), "5" (permanent failure)
	Subject string // "0" (other), "1" (addressing), "2" (mailbox), "3" (mail system)
	Detail  string // Details (0-99)
}

// Common Status Codes (RFC 3463)
var (
	StatusSucceeded          = "2.1.5" // Destination address valid
	StatusMalformedAddress   = "5.1.3" // Bad destination mailbox address
	StatusUnknownUser        = "5.1.1" // Bad destination mailbox
	StatusRelayDenied        = "5.7.1" // Relay denied
	StatusMailboxFull        = "4.2.2" // Mailbox full (temporary)
	StatusMessageTooLarge    = "5.3.4" // Message too large
	StatusServiceUnavailable = "4.3.2" // Service unavailable
	StatusSystemFull         = "5.3.5" // System full
	StatusNetworkError       = "4.4.2" // Bad connection
	StatusProtocolError      = "5.5.3" // Protocol error
)

// GenerateDSNReport creates a DSN report message.
// Returns the DSN as JSON (which will be part of the multipart DSN message).
func GenerateDSNReport(
	reportingMTA string,
	finalRecipient string,
	action string, // "delivered", "failed", "delayed"
	statusCode string, // e.g., "5.1.1"
	diagnosticCode string, // e.g., "smtp; 550 5.1.1 user unknown"
	originalRecipient string,
) (*DSNMessage, error) {

	dsn := &DSNMessage{
		ReportingMTA:      reportingMTA,
		ArrivalDate:       time.Now().UTC(),
		FinalRecipient:    finalRecipient,
		LastAttemptDate:   time.Now().UTC(),
		Action:            action,
		Status:            statusCode,
		DiagnosticCode:    diagnosticCode,
		OriginalRecipient: originalRecipient,
	}

	return dsn, nil
}

// ToJSON serializes DSN to JSON.
func (d *DSNMessage) ToJSON() string {
	data, _ := json.MarshalIndent(d, "", "  ")
	return string(data)
}

// BuildDSNHeaders returns RFC 3464 compliant DSN message headers.
func BuildDSNHeaders(
	from string,
	to string,
	subject string,
	originalMessageID string,
	reportingMTA string,
) map[string]string {
	return map[string]string{
		"From":                from,
		"To":                  to,
		"Subject":             subject,
		"Date":                time.Now().UTC().Format(time.RFC1123Z),
		"Message-ID":          fmt.Sprintf("<%d.%s>", time.Now().UnixNano(), reportingMTA),
		"Content-Type":        "multipart/report; report-type=delivery-status",
		"Original-Message-ID": originalMessageID,
		"X-Report-Type":       "delivery-status",
		"Reporting-MTA":       fmt.Sprintf("dns; %s", reportingMTA),
	}
}

// StatusCodeFromSMTPCode converts SMTP reply code to RFC 3463 status code.
func StatusCodeFromSMTPCode(smtpCode int) string {
	switch smtpCode {
	case 250:
		return StatusSucceeded
	case 451:
		return StatusServiceUnavailable
	case 452:
		return StatusMailboxFull
	case 500, 501, 502:
		return StatusProtocolError
	case 503:
		return StatusProtocolError
	case 550:
		return StatusUnknownUser
	case 551:
		return StatusUnknownUser
	case 552:
		return StatusMessageTooLarge
	case 553:
		return StatusMalformedAddress
	case 554:
		return StatusRelayDenied
	case 421:
		return StatusNetworkError
	default:
		if smtpCode >= 500 {
			return "5.0.0"
		}
		return "4.0.0"
	}
}

// BuildDSNMessage constructs an RFC 3464 multipart/report for one recipient.
// Non-failure reports return at most the original headers, regardless of RET.
func BuildDSNMessage(reportingMTA, recipient, originalRecipient, originalSender, action, diagnosticText string, smtpCode int, envID, returnType string, originalMessage []byte) (string, error) {
	return BuildDSNMessageWithSender(reportingMTA, "Mailer-Daemon@"+reportingMTA, recipient, originalRecipient, originalSender, action, diagnosticText, smtpCode, envID, returnType, originalMessage)
}

// BuildDSNMessageWithSender uses a validated server-configured visible sender.
// The SMTP envelope for a DSN remains null to prevent notification loops.
func BuildDSNMessageWithSender(reportingMTA, dsnSender, recipient, originalRecipient, originalSender, action, diagnosticText string, smtpCode int, envID, returnType string, originalMessage []byte) (string, error) {
	statusCode := StatusCodeFromSMTPCode(smtpCode)
	if action == "delayed" && (smtpCode < 400 || smtpCode >= 500) {
		statusCode = "4.0.0"
	}
	if action == "delivered" {
		statusCode = "2.0.0"
	}
	boundary := fmt.Sprintf("boundary-%d", time.Now().UnixNano())
	diagnosticText = strings.NewReplacer("\r", " ", "\n", " ").Replace(diagnosticText)
	utf8Report := !isASCII(recipient) || !isASCII(originalRecipient) || !isASCII(diagnosticText)
	utf8Original := !isASCII(string(dsnOriginalHeaders(originalMessage)))
	utf8Report = utf8Report || utf8Original
	statusType := "message/delivery-status"
	if utf8Report {
		statusType = "message/global-delivery-status"
	}
	now := time.Now().UTC()
	subject, explanation := "Delivery Status Notification", "Delivery status for"
	switch action {
	case "failed":
		subject += " (Failure)"
		explanation = "The following message could not be delivered to"
	case "delayed":
		subject += " (Delayed)"
		explanation = "Delivery has been delayed for"
	case "delivered":
		subject += " (Success)"
		explanation = "The message was successfully delivered to"
	default:
		return "", fmt.Errorf("unsupported DSN action %q", action)
	}

	var msg strings.Builder
	fmt.Fprintf(&msg, "From: %s\r\n", dsnSender)
	fmt.Fprintf(&msg, "To: %s\r\nSubject: %s\r\n", originalSender, subject)
	fmt.Fprintf(&msg, "Date: %s\r\n", now.Format(time.RFC1123Z))
	msg.WriteString("Auto-Submitted: auto-replied\r\nMIME-Version: 1.0\r\n")
	fmt.Fprintf(&msg, "Content-Type: multipart/report; report-type=delivery-status; boundary=\"%s\"\r\n", boundary)
	fmt.Fprintf(&msg, "Message-ID: <%d@%s>\r\n\r\n", now.UnixNano(), reportingMTA)
	fmt.Fprintf(&msg, "--%s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s: %s\r\n\r\n", boundary, explanation, recipient)
	fmt.Fprintf(&msg, "--%s\r\nContent-Type: %s\r\n\r\nReporting-MTA: dns; %s\r\n", boundary, statusType, reportingMTA)
	if envID != "" {
		fmt.Fprintf(&msg, "Original-Envelope-Id: %s\r\n", sanitizeDSNField(envID))
	}
	fmt.Fprintf(&msg, "Arrival-Date: %s\r\n\r\n", now.Format(time.RFC1123Z))
	if originalRecipient != "" {
		if strings.HasPrefix(originalRecipient, "utf-8;") {
			address := originalRecipient[len("utf-8;"):]
			if !utf8Report {
				address = encodeDSNUTF8Address(address)
			}
			fmt.Fprintf(&msg, "Original-Recipient: utf-8; %s\r\n", sanitizeDSNField(address))
		} else if !isASCII(originalRecipient) {
			fmt.Fprintf(&msg, "Original-Recipient: utf-8; %s\r\n", sanitizeDSNField(originalRecipient))
		} else {
			fmt.Fprintf(&msg, "Original-Recipient: rfc822; %s\r\n", sanitizeDSNField(originalRecipient))
		}
	}
	finalType, finalAddress := "rfc822", sanitizeDSNField(recipient)
	if !isASCII(recipient) {
		finalType = "utf-8"
	}
	fmt.Fprintf(&msg, "Final-Recipient: %s; %s\r\nAction: %s\r\nStatus: %s\r\n", finalType, finalAddress, action, statusCode)
	if diagnosticText != "" {
		if smtpCode > 0 {
			fmt.Fprintf(&msg, "Diagnostic-Code: smtp; %d %s\r\n", smtpCode, diagnosticText)
		} else {
			fmt.Fprintf(&msg, "Diagnostic-Code: X-GoMail; %s\r\n", diagnosticText)
		}
	}
	fmt.Fprintf(&msg, "Last-Attempt-Date: %s\r\n", now.Format(time.RFC1123Z))

	if len(originalMessage) > 0 {
		content := normalizeDSNCRLF(originalMessage)
		contentType := "message/rfc822"
		if action != "failed" || strings.EqualFold(returnType, "HDRS") {
			contentType = "text/rfc822-headers"
			content = dsnOriginalHeaders(content)
		}
		if utf8Original {
			if contentType == "message/rfc822" {
				contentType = "message/global"
			} else {
				contentType = "message/global-headers"
			}
		}
		fmt.Fprintf(&msg, "\r\n--%s\r\nContent-Type: %s\r\n\r\n", boundary, contentType)
		msg.Write(content)
		if !bytes.HasSuffix(content, []byte("\r\n")) {
			msg.WriteString("\r\n")
		}
	}
	fmt.Fprintf(&msg, "\r\n--%s--\r\n", boundary)
	return msg.String(), nil
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] > 127 {
			return false
		}
	}
	return true
}

// message/delivery-status is seven-bit; RFC 6533 defines unitext escapes
// for internationalized recipient fields in that legacy report format.
func encodeDSNUTF8Address(address string) string {
	var encoded strings.Builder
	for _, r := range address {
		if r > 126 || r <= 32 || r == 127 || r == '\\' || r == '+' || r == '=' {
			fmt.Fprintf(&encoded, `\x{%X}`, r)
		} else {
			encoded.WriteRune(r)
		}
	}
	return encoded.String()
}

func sanitizeDSNField(value string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(value)
}

func normalizeDSNCRLF(value []byte) []byte {
	value = bytes.ReplaceAll(value, []byte("\r\n"), []byte("\n"))
	value = bytes.ReplaceAll(value, []byte("\r"), []byte("\n"))
	return bytes.ReplaceAll(value, []byte("\n"), []byte("\r\n"))
}

func dsnOriginalHeaders(message []byte) []byte {
	if index := bytes.Index(message, []byte("\r\n\r\n")); index >= 0 {
		return message[:index+4]
	}
	return message
}
