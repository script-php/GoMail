package reporting

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
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
		return nil, fmt.Errorf("no TLS events found for %s", domain)
	}

	type policyGroup struct {
		policy   TLSPolicy
		failures map[string]*TLSFailure
		mx       map[string]bool
	}
	groups := make(map[string]*policyGroup)
	for _, event := range failures {
		desc := TLSPolicyDesc{PolicyType: event.PolicyType, PolicyString: event.PolicyString,
			PolicyDomain: event.PolicyDomain, MXHost: event.MXHostPattern}
		if desc.PolicyType == "" {
			desc.PolicyType = "no-policy-found"
		}
		if desc.PolicyDomain == "" {
			desc.PolicyDomain = domain
		}
		keyBytes, _ := json.Marshal(struct {
			Type   string
			Text   []string
			Domain string
		}{desc.PolicyType, desc.PolicyString, desc.PolicyDomain})
		key := string(keyBytes)
		group := groups[key]
		if group == nil {
			group = &policyGroup{policy: TLSPolicy{Policy: desc}, failures: make(map[string]*TLSFailure), mx: make(map[string]bool)}
			groups[key] = group
		}
		for _, mx := range event.MXHostPattern {
			group.mx[mx] = true
		}
		if event.Successful {
			group.policy.Summary.TotalSuccessfulSessionCount++
			continue
		}
		group.policy.Summary.TotalFailureSessionCount++
		detail := TLSFailure{ResultType: event.FailureReason, SendingMTAIP: event.SendingMTAIP,
			ReceivingMXHostname: event.ReceivingMXHostname, ReceivingIP: event.ReceivingIP,
			AdditionalInformation: event.AdditionalInformation, FailureReasonCode: event.FailureReasonCode}
		detailKeyBytes, _ := json.Marshal(detail)
		detailKey := string(detailKeyBytes)
		if existing := group.failures[detailKey]; existing != nil {
			existing.FailedSessionCount++
		} else {
			detail.FailedSessionCount = 1
			group.failures[detailKey] = &detail
		}
	}

	groupKeys := make([]string, 0, len(groups))
	for key := range groups {
		groupKeys = append(groupKeys, key)
	}
	sort.Strings(groupKeys)
	policies := make([]TLSPolicy, 0, len(groupKeys))
	for _, key := range groupKeys {
		group := groups[key]
		group.policy.Policy.MXHost = group.policy.Policy.MXHost[:0]
		for mx := range group.mx {
			group.policy.Policy.MXHost = append(group.policy.Policy.MXHost, mx)
		}
		sort.Strings(group.policy.Policy.MXHost)
		failureKeys := make([]string, 0, len(group.failures))
		for failureKey := range group.failures {
			failureKeys = append(failureKeys, failureKey)
		}
		sort.Strings(failureKeys)
		for _, failureKey := range failureKeys {
			group.policy.FailureDetails = append(group.policy.FailureDetails, *group.failures[failureKey])
		}
		policies = append(policies, group.policy)
	}

	// Build report
	// Keep the identifier stable for retries of the same UTC reporting window.
	// The address-shaped form also satisfies RFC 8460's Subject Report-ID syntax.
	reportID := fmt.Sprintf("%s+%s@%s", startTime.UTC().Format("2006.01.02T15.04.05Z"), domain, ourHostname)
	report := &TLSReport{
		OrganizationName: ourHostname,
		DateRange: TLSDateRange{
			StartDatetime: startTime.Format(time.RFC3339),
			EndDatetime:   endTime.Format(time.RFC3339),
		},
		ContactInfo: fmt.Sprintf("postmaster@%s", ourHostname),
		ReportID:    reportID,
		Policies:    policies,
	}

	return report, nil
}

// ExtractTLSRPTAddresses looks up the TLS-RPT DNS record for a domain and extracts all rua= addresses
// Returns a slice of email addresses from the rua= field (comma-separated)
func ExtractTLSRPTAddresses(domain string) ([]string, error) {
	endpoints, err := ExtractTLSRPTURIs(domain)
	if err != nil {
		return nil, err
	}
	var addresses []string
	for _, endpoint := range endpoints {
		parsed, _ := url.Parse(endpoint)
		if parsed.Scheme == "mailto" {
			addresses = append(addresses, parsed.Opaque)
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no mailto rua= address found in TLS-RPT record for %s", domain)
	}
	return addresses, nil
}

// ExtractTLSRPTURIs returns validated mailto and HTTPS report destinations.
func ExtractTLSRPTURIs(domain string) ([]string, error) {
	// Look up _smtp._tls.<domain> TXT record
	records, err := net.LookupTXT(fmt.Sprintf("_smtp._tls.%s", domain))
	if err != nil {
		return nil, fmt.Errorf("TLS-RPT DNS lookup failed for %s: %w", domain, err)
	}

	return parseTLSRPTRecords(records)
}

func parseTLSRPTRecords(records []string) ([]string, error) {
	var selected string
	for _, record := range records {
		if !tlsRPTVersionRecord(record) {
			continue
		}
		if selected != "" {
			return nil, fmt.Errorf("multiple TLS-RPT policy records")
		}
		selected = record
	}
	if selected == "" {
		return nil, fmt.Errorf("no TLS-RPT policy record")
	}
	return ParseTLSRPTRecord(selected)
}

func tlsRPTVersionRecord(record string) bool {
	const version = "v=TLSRPTv1"
	return strings.HasPrefix(record, version) && strings.HasPrefix(strings.TrimLeft(record[len(version):], " \t"), ";")
}

func ParseTLSRPTRecord(record string) ([]string, error) {
	if !tlsRPTVersionRecord(record) {
		return nil, fmt.Errorf("invalid TLS-RPT policy version")
	}
	tags := make(map[string]string)
	for _, part := range strings.Split(record, ";") {
		pair := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(pair) == 2 {
			key := strings.ToLower(pair[0])
			if _, exists := tags[key]; exists {
				return nil, fmt.Errorf("duplicate TLS-RPT tag %s", key)
			}
			tags[key] = strings.TrimSpace(pair[1])
		}
	}
	if tags["v"] != "TLSRPTv1" || tags["rua"] == "" {
		return nil, fmt.Errorf("invalid TLS-RPT policy")
	}
	var endpoints []string
	for _, raw := range strings.Split(tags["rua"], ",") {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		switch strings.ToLower(parsed.Scheme) {
		case "mailto":
			if parsed.Opaque == "" || parsed.RawQuery != "" {
				continue
			}
			if _, err := mail.ParseAddress(parsed.Opaque); err != nil {
				continue
			}
			endpoints = append(endpoints, "mailto:"+parsed.Opaque)
		case "https":
			if parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
				continue
			}
			endpoints = append(endpoints, parsed.String())
		}
	}
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("TLS-RPT policy has no supported rua destination")
	}
	return endpoints, nil
}

// PostTLSRPT sends a gzip-compressed report to an RFC 8460 HTTPS endpoint.
func PostTLSRPT(ctx context.Context, client *http.Client, endpoint string, report *TLSReport) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("invalid TLS-RPT HTTPS endpoint")
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encoding TLS-RPT report: %w", err)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(reportJSON); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(compressed.Bytes()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/tlsrpt+gzip")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("posting TLS-RPT report: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("TLS-RPT endpoint returned HTTP %d", response.StatusCode)
	}
	return nil
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
func BuildTLSRPTEmail(ourHostname, senderEmail, reportDomain string, report *TLSReport, recipientEmail string) string {
	reportJSON, _ := json.MarshalIndent(report, "", "  ")

	// Gzip compress the JSON (RFC 8460 requirement)
	var compressedBuf bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressedBuf)
	gzipWriter.Write(reportJSON)
	gzipWriter.Close()

	// Base64 encode the compressed data
	encodedReport := foldBase64(base64.StdEncoding.EncodeToString(compressedBuf.Bytes()))
	start, _ := time.Parse(time.RFC3339, report.DateRange.StartDatetime)
	end, _ := time.Parse(time.RFC3339, report.DateRange.EndDatetime)
	filename := fmt.Sprintf("%s!%s!%d!%d!001.json.gz", ourHostname, reportDomain, start.Unix(), end.Unix())

	// Build multipart email with gzip-compressed JSON report as attachment
	boundary := "boundary_tlsrpt"
	message := fmt.Sprintf(
		"From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: Report Domain: %s Submitter: %s Report-ID: <%s>\r\n"+
			"Date: %s\r\n"+
			"Message-ID: <%s>\r\n"+
			"TLS-Report-Domain: %s\r\n"+
			"TLS-Report-Submitter: %s\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: multipart/report; report-type=\"tlsrpt\"; boundary=\"%s\"\r\n"+
			"\r\n"+
			"--%s\r\n"+
			"Content-Type: text/plain; charset=UTF-8\r\n"+
			"\r\n"+
			"This is an aggregate TLS report from %s\r\n"+
			"\r\n"+
			"--%s\r\n"+
			"Content-Type: application/tlsrpt+gzip\r\n"+
			"Content-Transfer-Encoding: base64\r\n"+
			"Content-Disposition: attachment; filename=\"%s\"\r\n"+
			"\r\n"+
			"%s\r\n"+
			"--%s--\r\n",
		senderEmail,
		recipientEmail,
		reportDomain,
		ourHostname,
		report.ReportID,
		time.Now().Format(time.RFC1123Z),
		report.ReportID,
		reportDomain,
		ourHostname,
		boundary,
		boundary,
		ourHostname,
		boundary,
		filename,
		encodedReport,
		boundary,
	)

	return message
}

func foldBase64(value string) string {
	var result strings.Builder
	for len(value) > 76 {
		result.WriteString(value[:76])
		result.WriteString("\r\n")
		value = value[76:]
	}
	result.WriteString(value)
	return result.String()
}
