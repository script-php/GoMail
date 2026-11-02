package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	stdmail "net/mail"
	"regexp"
	"strings"
)

// DSNReport represents a Delivery Status Notification (RFC 3464)
type DSNReport struct {
	OriginalMessageID string            // Original-Message-ID from the message that failed
	OriginalRecipient string            // Original recipient that failed
	Status            string            // DSN Status code (e.g., "5.1.2")
	DiagnosticCode    string            // Remote SMTP diagnostic code (e.g., "smtp; 550 5.1.2 user unknown")
	Action            string            // Action (e.g., "failed", "delayed")
	RemoteMTA         string            // Remote server that rejected (if available)
	LastAttemptDate   string            // Last attempt timestamp
	RecipientsStatus  []RecipientStatus // Per-recipient status info
}

// RecipientStatus represents status for a single recipient in DSN
type RecipientStatus struct {
	FinalRecipient    string // Final-Recipient: rfc822; user@example.com
	Status            string // Status: 5.1.2
	Action            string // Action: failed
	DiagnosticCode    string // Diagnostic-Code: smtp; 550 text
	RemoteMTA         string // Remote-MTA: dns; hostname
	LastAttemptDate   string // Last-Attempt-Date: timestamp
	OriginalRecipient string // X-Original-Recipient: if present
}

// ParseDSN parses a DSN message and extracts delivery failure information.
// Accepts either just the text body or the full raw message (for multipart DSNs).
// For multipart DSNs, it extracts the message/delivery-status part automatically.
// Returns the DSN structure with recipient status details.
func ParseDSN(body string) (*DSNReport, error) {
	report := &DSNReport{
		RecipientsStatus: []RecipientStatus{},
	}

	// Extract delivery-status part from multipart DSN if present
	dsnBody := extractDeliveryStatusPart(body)
	if dsnBody == "" {
		dsnBody = body // Fall back to original body if extraction fails
	}

	scanner := bufio.NewScanner(strings.NewReader(unfoldDSNHeaders(dsnBody)))

	// State machine for parsing DSN (RFC 3464):
	// First: human-readable part (skip)
	// Then: message/delivery-status with per-message and per-recipient sections

	inPerRecipientFields := false
	currentRecipient := RecipientStatus{}

	headerRegex := regexp.MustCompile(`^([^:]+):\s*(.+)$`)

	for scanner.Scan() {
		line := scanner.Text()

		// Empty line often separates sections
		if line == "" {
			if inPerRecipientFields && currentRecipient.FinalRecipient != "" {
				// Save current recipient and start new one
				report.RecipientsStatus = append(report.RecipientsStatus, currentRecipient)
				currentRecipient = RecipientStatus{}
			}
			continue
		}

		// Match header: value
		matches := headerRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		key := strings.TrimSpace(matches[1])
		value := strings.TrimSpace(matches[2])

		// Normalize key to handle case variations
		key = strings.ToLower(key)

		// Parse per-message fields
		switch key {
		case "reporting-mta":
			// Start of per-message section (optional)
		case "original-message-id", "x-original-message-id":
			report.OriginalMessageID = value
		case "original-recipient", "x-original-recipient":
			if report.OriginalRecipient == "" {
				report.OriginalRecipient = dsnAddress(value)
			}
		case "arrival-date":
			// Skip, not needed for bounce tracking
		}

		// Per-recipient fields (come after "Final-Recipient:" header)
		switch key {
		case "final-recipient":
			if currentRecipient.FinalRecipient != "" {
				report.RecipientsStatus = append(report.RecipientsStatus, currentRecipient)
				currentRecipient = RecipientStatus{}
			}
			inPerRecipientFields = true
			// Format: rfc822; user@example.com
			parts := strings.SplitN(value, ";", 2)
			if len(parts) == 2 {
				currentRecipient.FinalRecipient = strings.TrimSpace(parts[1])
			}
		case "action":
			currentRecipient.Action = value
			if report.Action == "" {
				report.Action = value
			}
		case "status":
			currentRecipient.Status = value
			if report.Status == "" {
				report.Status = value
			}
		case "diagnostic-code":
			currentRecipient.DiagnosticCode = value
			if report.DiagnosticCode == "" {
				report.DiagnosticCode = value
			}
		case "remote-mta":
			// Format: dns; hostname
			parts := strings.SplitN(value, ";", 2)
			if len(parts) == 2 {
				currentRecipient.RemoteMTA = strings.TrimSpace(parts[1])
			}
			report.RemoteMTA = currentRecipient.RemoteMTA
		case "last-attempt-date":
			currentRecipient.LastAttemptDate = value
			report.LastAttemptDate = value
		case "original-recipient", "x-original-recipient":
			currentRecipient.OriginalRecipient = dsnAddress(value)
			if report.OriginalRecipient == "" {
				report.OriginalRecipient = currentRecipient.OriginalRecipient
			}
		}
	}

	// Don't forget the last recipient
	if inPerRecipientFields && currentRecipient.FinalRecipient != "" {
		report.RecipientsStatus = append(report.RecipientsStatus, currentRecipient)
	}

	if len(report.RecipientsStatus) == 0 && report.OriginalRecipient == "" {
		return nil, fmt.Errorf("no recipient status found in DSN")
	}

	return report, nil
}

// ExtractBounceType determines bounce type from DSN status code
// Status codes: 2.x.x (success), 4.x.x (temporary), 5.x.x (permanent)
func ExtractBounceType(statusCode string) string {
	parts := strings.SplitN(statusCode, ".", 2)
	if len(parts) == 0 {
		return "unknown"
	}

	switch parts[0] {
	case "2":
		return "success"
	case "4":
		return "temporary"
	case "5":
		return "permanent"
	default:
		return "unknown"
	}
}

// ExtractSMTPCode extracts numeric SMTP code from diagnostic-code
// Format: "smtp; 550 5.1.1 user unknown"
func ExtractSMTPCode(diagnosticCode string) int {
	// Look for SMTP code (3 digits)
	re := regexp.MustCompile(`\b(\d{3})\b`)
	matches := re.FindStringSubmatch(diagnosticCode)
	if len(matches) > 1 {
		var code int
		fmt.Sscanf(matches[1], "%d", &code)
		return code
	}
	return 0
}

// IsDSNMessage checks if a message is a Delivery Status Notification
// by looking for typical DSN indicators
func IsDSNMessage(subject string, headers map[string][]string, body string) bool {
	// Check subject
	if strings.Contains(strings.ToLower(subject), "delivery status") ||
		strings.Contains(strings.ToLower(subject), "mail delivery failed") ||
		strings.Contains(strings.ToLower(subject), "undeliverable") ||
		strings.Contains(strings.ToLower(subject), "failure notice") {
		return true
	}

	// Check headers for DSN indicators
	if headers != nil {
		if contentType, ok := headers["Content-Type"]; ok {
			for _, ct := range contentType {
				if strings.Contains(strings.ToLower(ct), "delivery-status") {
					return true
				}
			}
		}
	}

	// Check body for DSN structure keywords
	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "final-recipient") ||
		strings.Contains(bodyLower, "delivery status") ||
		strings.Contains(bodyLower, "diagnostic-code") {
		return true
	}

	return false
}

// extractDeliveryStatusPart extracts the message/delivery-status MIME part from a multipart DSN.
// Multipart DSNs have format:
//
//	--boundary
//	Content-Type: text/plain
//	...text part...
//	--boundary
//	Content-Type: message/delivery-status
//	...headers...
//	--boundary--
func extractDeliveryStatusPart(fullBody string) string {
	message, err := stdmail.ReadMessage(strings.NewReader(fullBody))
	if err != nil {
		return ""
	}
	content, err := findDeliveryStatusPart(message.Header.Get("Content-Type"), message.Body, 0)
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(content), "\r\n")
}

func findDeliveryStatusPart(contentType string, body io.Reader, depth int) ([]byte, error) {
	if depth > 10 {
		return nil, fmt.Errorf("MIME nesting exceeds limit")
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(mediaType, "message/delivery-status") {
		return io.ReadAll(io.LimitReader(body, 4<<20))
	}
	if !strings.HasPrefix(strings.ToLower(mediaType), "multipart/") || params["boundary"] == "" {
		return nil, fmt.Errorf("delivery-status part not found")
	}
	reader := multipart.NewReader(body, params["boundary"])
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(part, 4<<20))
		part.Close()
		if readErr != nil {
			return nil, readErr
		}
		if found, err := findDeliveryStatusPart(part.Header.Get("Content-Type"), bytes.NewReader(data), depth+1); err == nil {
			return found, nil
		}
	}
	return nil, fmt.Errorf("delivery-status part not found")
}

func unfoldDSNHeaders(body string) string {
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	var unfolded []string
	for _, line := range lines {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && len(unfolded) > 0 && unfolded[len(unfolded)-1] != "" {
			unfolded[len(unfolded)-1] += " " + strings.TrimSpace(line)
			continue
		}
		unfolded = append(unfolded, strings.TrimSuffix(line, "\r"))
	}
	return strings.Join(unfolded, "\n")
}

func dsnAddress(value string) string {
	parts := strings.SplitN(value, ";", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return strings.TrimSpace(value)
}
