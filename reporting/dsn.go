package reporting

import (
	"encoding/json"
	"fmt"
	"time"
)

// DSNRequest represents DSN parameters from MAIL FROM or RCPT TO.
// RFC 3461 - SMTP Service Extension for Delivery Status Notifications
type DSNRequest struct {
	NotifyFlags string // "SUCCESS", "FAILURE", "DELAY", "NEVER" (comma-separated)
	ReturnType  string // "FULL" or "HDRS"
	OrigRecipient string // Original recipient address (ORCPT)
	EnvID        string // Envelope ID
}

// DSNMessage represents a complete DSN report (both per-message and per-recipient info).
type DSNMessage struct {
	ReportingMTA     string              `json:"reporting_mta"`
	DSNGateway       string              `json:"dsn_gateway,omitempty"`
	ArrivalDate      time.Time           `json:"arrival_date"`
	MessageID        string              `json:"message_id"`
	OriginalRecipient string             `json:"original_recipient,omitempty"`
	FinalRecipient   string              `json:"final_recipient"`
	Action           string              `json:"action"` // delivered, failed, delayed
	Status           string              `json:"status"` // RFC 3463 status code (e.g., "5.1.1")
	DiagnosticCode   string              `json:"diagnostic_code,omitempty"` // RFC 3463 code
	LastAttemptDate  time.Time           `json:"last_attempt_date"`
	WillRetryUntil   *time.Time          `json:"will_retry_until,omitempty"` // For delayed
	RemoteMTA        string              `json:"remote_mta,omitempty"`
	RemoteDiagnostic string              `json:"remote_diagnostic,omitempty"`
}

// StatusCode represents RFC 3463 Enhanced Mail System Status Codes.
type StatusCode struct {
	Class  string // "2" (success), "4" (persistent temp failure), "5" (permanent failure)
	Subject string // "0" (other), "1" (addressing), "2" (mailbox), "3" (mail system)
	Detail string // Details (0-99)
}

// Common Status Codes (RFC 3463)
var (
	StatusSucceeded = "2.1.5"            // Destination address valid
	StatusMalformedAddress = "5.1.3"     // Bad destination mailbox address
	StatusUnknownUser = "5.1.1"          // Bad destination mailbox
	StatusRelayDenied = "5.7.1"          // Relay denied
	StatusMailboxFull = "4.2.2"          // Mailbox full (temporary)
	StatusMessageTooLarge = "5.3.4"      // Message too large
	StatusServiceUnavailable = "4.3.2"   // Service unavailable
	StatusSystemFull = "5.3.5"           // System full
	StatusNetworkError = "4.4.2"         // Bad connection
	StatusProtocolError = "5.5.3"        // Protocol error
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
		"From":                      from,
		"To":                        to,
		"Subject":                   subject,
		"Date":                      time.Now().UTC().Format(time.RFC1123Z),
		"Message-ID":                fmt.Sprintf("<%d.%s>", time.Now().UnixNano(), reportingMTA),
		"Content-Type":              "multipart/report; report-type=delivery-status",
		"Original-Message-ID":       originalMessageID,
		"X-Report-Type":             "delivery-status",
		"Reporting-MTA":             fmt.Sprintf("dns; %s", reportingMTA),
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
