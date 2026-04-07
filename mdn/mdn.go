package mdn

import (
	"fmt"
	"strings"
	"time"

	"gomail/config"
)

// GenerateMDN creates a Message Disposition Notification (RFC 3798) in simple text format
// Returns: the MDN message as a single text/plain email (not multipart/report for simplicity)
func GenerateMDN(originalMessageID, originalSubject, recipientEmail, senderEmail, hostname string) string {
	now := time.Now()
	mdnMessageID := fmt.Sprintf("<%d.mdn@%s>", now.UnixNano(), hostname)

	var msg strings.Builder

	// Received header - GoMail auto-generated MDN
	msg.WriteString(fmt.Sprintf("Received: by %s (GoMail)\r\n\tid %s\r\n\tfor <%s>;\r\n\t%s\r\n",
		hostname,
		mdnMessageID,
		senderEmail,
		now.Format(time.RFC1123Z),
	))
	msg.WriteString(fmt.Sprintf("From: %s\r\n", recipientEmail))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", senderEmail))
	msg.WriteString(fmt.Sprintf("Subject: Read: %s\r\n", originalSubject))
	msg.WriteString(fmt.Sprintf("Date: %s\r\n", now.Format(time.RFC1123Z)))
	msg.WriteString(fmt.Sprintf("Message-ID: %s\r\n", mdnMessageID))
	msg.WriteString(fmt.Sprintf("In-Reply-To: %s\r\n", originalMessageID))
	msg.WriteString(fmt.Sprintf("User-Agent: %s\r\n", config.UserAgent()))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	msg.WriteString("X-Mailer: GoMail\r\n")
	msg.WriteString("\r\n")

	// Body - simple text notification
	msg.WriteString("Your message has been displayed.\r\n")
	msg.WriteString("\r\n")
	msg.WriteString("---\r\n")
	msg.WriteString(fmt.Sprintf("Original Message ID: %s\r\n", originalMessageID))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", originalSubject))
	msg.WriteString(fmt.Sprintf("Displayed by: %s\r\n", recipientEmail))
	msg.WriteString(fmt.Sprintf("Displayed at: %s\r\n", now.Format(time.RFC3339)))

	return msg.String()
}

// GenerateMDNMultipart creates a proper RFC 3798 multipart/report MDN
// This is a more complete implementation
func GenerateMDNMultipart(originalMessageID, originalSubject, recipientEmail, senderEmail, hostname string) string {
	now := time.Now()
	mdnMessageID := fmt.Sprintf("<%d.mdn@%s>", now.UnixNano(), hostname)
	boundary := fmt.Sprintf("mdn-boundary-%d", now.UnixNano())

	var msg strings.Builder

	// Headers
	msg.WriteString(fmt.Sprintf("Received: by %s (GoMail)\r\n\tid %s\r\n\tfor <%s>;\r\n\t%s\r\n",
		hostname,
		mdnMessageID,
		senderEmail,
		now.Format(time.RFC1123Z),
	))
	msg.WriteString(fmt.Sprintf("From: %s\r\n", recipientEmail))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", senderEmail))
	msg.WriteString(fmt.Sprintf("Subject: Read: %s\r\n", originalSubject))
	msg.WriteString(fmt.Sprintf("Date: %s\r\n", now.Format(time.RFC1123Z)))
	msg.WriteString(fmt.Sprintf("Message-ID: %s\r\n", mdnMessageID))
	msg.WriteString(fmt.Sprintf("In-Reply-To: %s\r\n", originalMessageID))
	msg.WriteString(fmt.Sprintf("User-Agent: %s\r\n", config.UserAgent()))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString(fmt.Sprintf("Content-Type: multipart/report; report-type=disposition-notification; boundary=\"%s\"\r\n", boundary))
	msg.WriteString("X-Mailer: GoMail\r\n")
	msg.WriteString("\r\n")

	// Part 1: Human-readable explanation
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	msg.WriteString("\r\n")
	msg.WriteString("Your message has been displayed.\r\n")
	msg.WriteString("\r\n")

	// Part 2: Machine-readable disposition notification
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: message/disposition-notification\r\n")
	msg.WriteString("Content-Transfer-Encoding: 7bit\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(fmt.Sprintf("Reporting-UA: GoMail; %s\r\n", hostname))
	msg.WriteString(fmt.Sprintf("Original-Recipient: rfc822; %s\r\n", recipientEmail))
	msg.WriteString(fmt.Sprintf("Final-Recipient: rfc822; %s\r\n", recipientEmail))
	msg.WriteString(fmt.Sprintf("Original-Message-ID: %s\r\n", originalMessageID))
	msg.WriteString(fmt.Sprintf("Disposition: automatic-action/MDN-sent-automatically; displayed\r\n"))
	msg.WriteString("\r\n") // Blank line after fields (required by RFC 3798)

	// End boundary
	msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	return msg.String()
}
