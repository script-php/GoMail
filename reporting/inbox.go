package reporting

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"sync"
	"time"

	"gomail/logging"
	"gomail/store"
)

const (
	maxReportMessage    = 4 << 20
	maxReportCompressed = 4 << 20
	maxReportDecoded    = 16 << 20
)

var receivedReportScanMu sync.Mutex

// ScanReceivedReports reads only the explicitly selected local mailbox.
// Source messages remain untouched; the durable cursor and unique history key
// make repeated scans safe after crashes or concurrent manual scans.
func ScanReceivedReports(db *store.DB) (int, error) {
	receivedReportScanMu.Lock()
	defer receivedReportScanMu.Unlock()
	return scanReceivedReports(db)
}

// RescanReceivedReports safely starts a deduplicated history rescan, including
// earlier messages skipped before a parser improvement.
func RescanReceivedReports(db *store.DB) (int, error) {
	receivedReportScanMu.Lock()
	defer receivedReportScanMu.Unlock()
	settings, err := db.GetReportInboxSettings()
	if err != nil || !settings.Enabled {
		return 0, err
	}
	if err := db.ResetReportInboxFailureRetries(settings.AccountID); err != nil {
		return 0, err
	}
	if err := db.ResetReportInboxCursor(settings.AccountID); err != nil {
		return 0, err
	}
	return scanReceivedReports(db)
}

func scanReceivedReports(db *store.DB) (int, error) {
	settings, err := db.GetReportInboxSettings()
	if err != nil || !settings.Enabled {
		return 0, err
	}
	account, err := db.GetAccount(settings.AccountID)
	if err != nil {
		return 0, err
	}
	if account == nil || !account.IsActive {
		return 0, fmt.Errorf("selected report mailbox is no longer active")
	}
	domains, err := db.ListDomains()
	if err != nil {
		return 0, err
	}
	hosted := make(map[string]bool, len(domains))
	for _, domain := range domains {
		if domain.IsActive {
			hosted[normalizeReportDomain(domain.Domain)] = true
		}
	}
	imported := 0
	process := func(message store.ReportSourceMessage) error {
		if len(message.Raw) == 0 || len(message.Raw) > maxReportMessage {
			return db.ClearReportInboxFailure(settings.AccountID, message.ID)
		}
		reports, parseErr := parseReceivedReportMessage(message.Raw)
		if parseErr != nil {
			logging.Warn(fmt.Sprintf("[report-inbox] message %d: %v", message.ID, parseErr))
		}
		for _, report := range reports {
			scoped, err := scopeReceivedReport(report, hosted)
			if err != nil {
				parseErr = err
				continue
			}
			for _, item := range scoped {
				item.AccountID, item.SourceMessageID = settings.AccountID, message.ID
				inserted, err := db.SaveReceivedReport(item)
				if err != nil {
					return err
				}
				if inserted {
					imported++
				}
			}
		}
		if parseErr != nil {
			return db.MarkReportInboxFailure(settings.AccountID, message.ID, parseErr)
		}
		return db.ClearReportInboxFailure(settings.AccountID, message.ID)
	}
	retries, err := db.RetryableReportMessages(settings.AccountID, 20)
	if err != nil {
		return 0, err
	}
	for _, message := range retries {
		if err := process(message); err != nil {
			return imported, err
		}
	}
	for batch := 0; batch < 10; batch++ {
		messages, err := db.ReportSourceMessages(settings.AccountID, settings.LastMessageID, 100)
		if err != nil {
			return imported, err
		}
		for _, message := range messages {
			if err := process(message); err != nil {
				return imported, err
			}
			if err := db.AdvanceReportInboxCursor(settings.AccountID, message.ID); err != nil {
				return imported, err
			}
			settings.LastMessageID = message.ID
		}
		if len(messages) < 100 {
			break
		}
	}
	return imported, nil
}

func normalizeReportDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// A shared report mailbox may receive reports for domains hosted elsewhere.
// TLS-RPT can also contain policies for multiple domains in one attachment.
func scopeReceivedReport(report store.ReceivedReport, hosted map[string]bool) ([]store.ReceivedReport, error) {
	if report.Kind != "tls-rpt" {
		if hosted[normalizeReportDomain(report.ReportDomain)] {
			return []store.ReceivedReport{report}, nil
		}
		return nil, nil
	}
	var payload TLSReport
	if err := json.Unmarshal([]byte(report.PayloadJSON), &payload); err != nil {
		return nil, err
	}
	grouped := make(map[string][]TLSPolicy)
	for _, policy := range payload.Policies {
		domain := normalizeReportDomain(policy.Policy.PolicyDomain)
		if hosted[domain] {
			grouped[domain] = append(grouped[domain], policy)
		}
	}
	var results []store.ReceivedReport
	for domain, policies := range grouped {
		item := report
		item.ReportDomain = domain
		item.Successes, item.Failures = 0, 0
		for _, policy := range policies {
			item.Successes += int64(policy.Summary.TotalSuccessfulSessionCount)
			item.Failures += int64(policy.Summary.TotalFailureSessionCount)
		}
		filtered := payload
		filtered.Policies = policies
		data, err := json.Marshal(filtered)
		if err != nil {
			return nil, err
		}
		item.PayloadJSON = string(data)
		results = append(results, item)
	}
	return results, nil
}

// RunReceivedReportScanner follows live settings; disabled is the default.
func RunReceivedReportScanner(db *store.DB) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if _, err := ScanReceivedReports(db); err != nil {
					logging.Warn(fmt.Sprintf("[report-inbox] scan failed: %v", err))
				}
			}
		}
	}()
	return func() { close(stop); <-done }
}

func parseReceivedReportMessage(raw []byte) ([]store.ReceivedReport, error) {
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	var reports []store.ReceivedReport
	var walk func(io.Reader, string, string, string, int) error
	walk = func(body io.Reader, contentType, filename, transferEncoding string, depth int) error {
		if depth > 4 {
			return fmt.Errorf("MIME nesting too deep")
		}
		mediaType, params, err := mime.ParseMediaType(contentType)
		if err != nil {
			return nil
		}
		if filename == "" {
			filename = params["name"]
		}
		if strings.HasPrefix(mediaType, "multipart/") {
			reader := multipart.NewReader(body, params["boundary"])
			var firstErr error
			for {
				part, err := reader.NextPart()
				if err == io.EOF {
					return firstErr
				}
				if err != nil {
					return err
				}
				if err := walk(part, part.Header.Get("Content-Type"), part.FileName(), part.Header.Get("Content-Transfer-Encoding"), depth+1); err != nil {
					if firstErr == nil {
						firstErr = err
					}
				}
			}
		}
		kind := ""
		lowerName := strings.ToLower(filename)
		switch {
		case strings.HasPrefix(mediaType, "application/tlsrpt+"), strings.HasSuffix(lowerName, ".json.gz"), strings.HasSuffix(lowerName, ".json"):
			kind = "tls-rpt"
		case mediaType == "application/xml", mediaType == "text/xml", mediaType == "application/zip", mediaType == "application/gzip", strings.HasSuffix(lowerName, ".xml"), strings.HasSuffix(lowerName, ".xml.gz"), strings.HasSuffix(lowerName, ".zip"):
			kind = "dmarc"
		default:
			return nil
		}
		encoded, err := io.ReadAll(io.LimitReader(body, maxReportCompressed+1))
		if err != nil || len(encoded) > maxReportCompressed {
			return fmt.Errorf("report attachment exceeds compressed size limit")
		}
		if strings.EqualFold(transferEncoding, "base64") {
			encoded, err = io.ReadAll(io.LimitReader(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(encoded)), maxReportCompressed+1))
			if err != nil || len(encoded) > maxReportCompressed {
				return fmt.Errorf("invalid or oversized base64 report attachment")
			}
		} else if strings.EqualFold(transferEncoding, "quoted-printable") {
			encoded, err = io.ReadAll(io.LimitReader(quotedprintable.NewReader(bytes.NewReader(encoded)), maxReportCompressed+1))
			if err != nil || len(encoded) > maxReportCompressed {
				return fmt.Errorf("invalid or oversized quoted-printable report attachment")
			}
		}
		decoded, err := decodeReportAttachment(encoded, lowerName, mediaType)
		if err != nil {
			return err
		}
		report, err := parseReportPayload(kind, decoded)
		if err != nil {
			return err
		}
		reports = append(reports, report)
		return nil
	}
	err = walk(message.Body, message.Header.Get("Content-Type"), "", message.Header.Get("Content-Transfer-Encoding"), 0)
	return reports, err
}

func decodeReportAttachment(encoded []byte, filename, mediaType string) ([]byte, error) {
	data := encoded
	if strings.HasSuffix(filename, ".zip") || mediaType == "application/zip" {
		archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		if len(archive.File) != 1 {
			return nil, fmt.Errorf("report ZIP must contain one file")
		}
		reader, err := archive.File[0].Open()
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return readBoundedReport(reader)
	}
	if strings.HasSuffix(filename, ".gz") || strings.HasSuffix(mediaType, "+gzip") || mediaType == "application/gzip" {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return readBoundedReport(reader)
	}
	if len(data) > maxReportDecoded {
		return nil, fmt.Errorf("report exceeds decoded size limit")
	}
	return data, nil
}

func readBoundedReport(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxReportDecoded+1))
	if err != nil || len(data) > maxReportDecoded {
		return nil, fmt.Errorf("report exceeds decoded size limit")
	}
	return data, nil
}

func parseReportPayload(kind string, data []byte) (store.ReceivedReport, error) {
	var result store.ReceivedReport
	result.Kind = kind
	switch kind {
	case "dmarc":
		var report DMARCReport
		if err := xml.Unmarshal(data, &report); err != nil || report.XMLName.Local != "feedback" || report.Policy.Domain == "" {
			return result, fmt.Errorf("invalid DMARC aggregate report")
		}
		if report.Metadata.DateRange.End <= report.Metadata.DateRange.Begin {
			return result, fmt.Errorf("invalid DMARC report period")
		}
		result.ReportDomain, result.Submitter, result.ReportID = report.Policy.Domain, report.Metadata.OrgName, report.Metadata.ReportID
		result.PeriodStart, result.PeriodEnd = time.Unix(report.Metadata.DateRange.Begin, 0).UTC().Format(time.RFC3339), time.Unix(report.Metadata.DateRange.End, 0).UTC().Format(time.RFC3339)
		for _, record := range report.Records {
			if record.Row.Count < 0 {
				return result, fmt.Errorf("negative DMARC count")
			}
			if record.Row.PolicyEval.DKIM == "pass" || record.Row.PolicyEval.SPF == "pass" {
				result.Successes += int64(record.Row.Count)
			} else {
				result.Failures += int64(record.Row.Count)
			}
		}
	case "tls-rpt":
		var report TLSReport
		if err := json.Unmarshal(data, &report); err != nil || report.ReportID == "" || len(report.Policies) == 0 {
			return result, fmt.Errorf("invalid TLS-RPT report")
		}
		start, startErr := time.Parse(time.RFC3339, report.DateRange.StartDatetime)
		end, endErr := time.Parse(time.RFC3339, report.DateRange.EndDatetime)
		if startErr != nil || endErr != nil || !end.After(start) {
			return result, fmt.Errorf("invalid TLS-RPT report period")
		}
		result.ReportDomain, result.Submitter, result.ReportID = report.Policies[0].Policy.PolicyDomain, report.OrganizationName, report.ReportID
		result.PeriodStart, result.PeriodEnd = report.DateRange.StartDatetime, report.DateRange.EndDatetime
		for _, policy := range report.Policies {
			if policy.Summary.TotalSuccessfulSessionCount < 0 || policy.Summary.TotalFailureSessionCount < 0 {
				return result, fmt.Errorf("negative TLS-RPT count")
			}
			result.Successes += int64(policy.Summary.TotalSuccessfulSessionCount)
			result.Failures += int64(policy.Summary.TotalFailureSessionCount)
		}
	}
	if result.ReportDomain == "" || result.ReportID == "" {
		return result, fmt.Errorf("report identity missing")
	}
	if len(result.ReportDomain) > 253 || len(result.Submitter) > 253 || len(result.ReportID) > 998 || len(result.PeriodStart) > 64 || len(result.PeriodEnd) > 64 {
		return result, fmt.Errorf("report metadata exceeds storage limits")
	}
	result.PayloadJSON = string(data)
	return result, nil
}
