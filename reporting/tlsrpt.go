package reporting

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"gomail/store"
)

// TLSReport represents a TLS-RPT report (RFC 8460).
type TLSReport struct {
	OrganizationName string       `json:"organization-name"`
	DateRange        TLSDateRange `json:"date-range"`
	ContactInfo      string       `json:"contact-info"`
	ReportID         string       `json:"report-id"`
	Policies         []TLSPolicy  `json:"policies"`
}

type TLSDateRange struct {
	StartDatetime string `json:"start-datetime"`
	EndDatetime   string `json:"end-datetime"`
}

type TLSPolicy struct {
	Policy         TLSPolicyDesc    `json:"policy"`
	Summary        TLSPolicySummary `json:"summary"`
	FailureDetails []TLSFailure     `json:"failure-details,omitempty"`
}

type TLSPolicyDesc struct {
	PolicyType   string   `json:"policy-type"`
	PolicyString []string `json:"policy-string"`
	PolicyDomain string   `json:"policy-domain"`
	MXHost       []string `json:"mx-host,omitempty"`
}

type TLSPolicySummary struct {
	TotalSuccessfulSessionCount int `json:"total-successful-session-count"`
	TotalFailureSessionCount    int `json:"total-failure-session-count"`
}

type TLSFailure struct {
	ResultType            string `json:"result-type"`
	SendingMTAIP          string `json:"sending-mta-ip,omitempty"`
	ReceivingMXHostname   string `json:"receiving-mx-hostname,omitempty"`
	ReceivingIP           string `json:"receiving-ip,omitempty"`
	FailedSessionCount    int    `json:"failed-session-count"`
	AdditionalInformation string `json:"additional-information,omitempty"`
	FailureReasonCode     string `json:"failure-reason-code,omitempty"`
}

// ParseTLSReport parses a TLS-RPT report from JSON.
func ParseTLSReport(r io.Reader) (*TLSReport, error) {
	var report TLSReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("parsing TLS report: %w", err)
	}
	return &report, nil
}

// GenerateTLSReport generates an RFC 8460 compliant TLS-RPT report for a domain
// within a time range based on recorded TLS failures
func GenerateTLSReport(db *store.DB, ourHostname string, domain string, startTime, endTime time.Time) (*TLSReport, error) {
	// Get all TLS failures for this domain in the time range
	failures, err := db.GetTLSFailuresForReport(domain, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("getting TLS failures: %w", err)
	}

	if len(failures) == 0 {
		return nil, fmt.Errorf("no TLS failures found for %s", domain)
	}

	// Group failures by reason
	reasonCounts := make(map[string]int)
	reasonDetails := make(map[string][]TLSFailure)

	for _, failure := range failures {
		reasonCounts[failure.FailureReason]++
		reasonDetails[failure.FailureReason] = append(reasonDetails[failure.FailureReason], TLSFailure{
			ResultType:          failure.FailureReason,
			SendingMTAIP:        failure.SendingMTAIP,
			ReceivingMXHostname: failure.ReceivingMXHostname,
			ReceivingIP:         failure.ReceivingIP,
			FailedSessionCount:  1,
		})
	}

	// Build policy entry
	policy := TLSPolicy{
		Policy: TLSPolicyDesc{
			PolicyType:   "tlsa", // DANE policy type
			PolicyDomain: domain,
			PolicyString: []string{"tlsa"}, // Indicate that failures are TLSA-related
		},
		Summary: TLSPolicySummary{
			TotalSuccessfulSessionCount: 0, // We only track failures
			TotalFailureSessionCount:    len(failures),
		},
	}

	// Aggregate failure details by reason
	for reason, details := range reasonDetails {
		aggregatedFailure := TLSFailure{
			ResultType:         reason,
			FailedSessionCount: len(details),
		}
		// Use first detail's info if available
		if len(details) > 0 {
			aggregatedFailure.SendingMTAIP = details[0].SendingMTAIP
			aggregatedFailure.ReceivingMXHostname = details[0].ReceivingMXHostname
			aggregatedFailure.ReceivingIP = details[0].ReceivingIP
		}
		policy.FailureDetails = append(policy.FailureDetails, aggregatedFailure)
	}

	// Build report
	reportID := fmt.Sprintf("%s.%d", domain, time.Now().Unix())
	report := &TLSReport{
		OrganizationName: ourHostname,
		DateRange: TLSDateRange{
			StartDatetime: startTime.Format(time.RFC3339),
			EndDatetime:   endTime.Format(time.RFC3339),
		},
		ContactInfo: fmt.Sprintf("postmaster@%s", ourHostname),
		ReportID:    reportID,
		Policies:    []TLSPolicy{policy},
	}

	return report, nil
}

// ExtractTLSRPTAddresses looks up the TLS-RPT DNS record for a domain and extracts all rua= addresses
// Returns a slice of email addresses from the rua= field (comma-separated)
func ExtractTLSRPTAddresses(domain string) ([]string, error) {
	// Look up _smtp._tls.<domain> TXT record
	records, err := net.LookupTXT(fmt.Sprintf("_smtp._tls.%s", domain))
	if err != nil {
		return nil, fmt.Errorf("TLS-RPT DNS lookup failed for %s: %w", domain, err)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no TLS-RPT record found for %s", domain)
	}

	// Parse the first TXT record looking for rua= addresses
	for _, record := range records {
		// Record should be: v=TLSRPTv1; rua=mailto:admin@example.com,mailto:admin2@example.com
		parts := strings.Split(record, ";")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "rua=") {
				rua := strings.TrimPrefix(part, "rua=")
				// Split by comma for multiple mailto: addresses
				var addresses []string
				for _, addr := range strings.Split(rua, ",") {
					addr = strings.TrimSpace(addr)
					// Extract email from mailto:
					if strings.HasPrefix(addr, "mailto:") {
						addresses = append(addresses, strings.TrimPrefix(addr, "mailto:"))
					} else {
						addresses = append(addresses, addr)
					}
				}
				if len(addresses) > 0 {
					return addresses, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no rua= address found in TLS-RPT record for %s", domain)
}

// ExtractTLSRPTAddress (deprecated: use ExtractTLSRPTAddresses instead)
// looks up the TLS-RPT DNS record for a domain and extracts the first rua= address
func ExtractTLSRPTAddress(domain string) (string, error) {
	addresses, err := ExtractTLSRPTAddresses(domain)
	if err != nil {
		return "", err
	}
	if len(addresses) == 0 {
		return "", fmt.Errorf("no rua= addresses found")
	}
	return addresses[0], nil
}

// BuildTLSRPTEmail creates an email message containing the TLS-RPT report
// RFC 8460: Report is gzip-compressed and base64-encoded
func BuildTLSRPTEmail(ourHostname, senderEmail string, report *TLSReport, recipientEmail string) string {
	reportJSON, _ := json.MarshalIndent(report, "", "  ")

	// Gzip compress the JSON (RFC 8460 requirement)
	var compressedBuf bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressedBuf)
	gzipWriter.Write(reportJSON)
	gzipWriter.Close()

	// Base64 encode the compressed data
	encodedReport := base64.StdEncoding.EncodeToString(compressedBuf.Bytes())

	// Build multipart email with gzip-compressed JSON report as attachment
	boundary := "boundary_tlsrpt"
	message := fmt.Sprintf(
		"From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: TLS Report for %s\r\n"+
			"Date: %s\r\n"+
			"Message-ID: <%s@%s>\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: multipart/mixed; boundary=\"%s\"\r\n"+
			"\r\n"+
			"--%s\r\n"+
			"Content-Type: text/plain; charset=UTF-8\r\n"+
			"\r\n"+
			"This is an automated TLS-RPT report for domain %s.\r\n"+
			"Report period: %s to %s\r\n"+
			"Failures recorded: %d\r\n"+
			"\r\n"+
			"--%s\r\n"+
			"Content-Type: application/gzip; name=\"report.json.gz\"\r\n"+
			"Content-Transfer-Encoding: base64\r\n"+
			"Content-Disposition: attachment; filename=\"report.json.gz\"\r\n"+
			"\r\n"+
			"%s\r\n"+
			"--%s--\r\n",
		senderEmail,
		recipientEmail,
		report.Policies[0].Policy.PolicyDomain,
		time.Now().Format(time.RFC1123Z),
		report.ReportID,
		ourHostname,
		boundary,
		boundary,
		report.Policies[0].Policy.PolicyDomain,
		report.DateRange.StartDatetime,
		report.DateRange.EndDatetime,
		report.Policies[0].Summary.TotalFailureSessionCount,
		boundary,
		encodedReport,
		boundary,
	)

	return message
}
