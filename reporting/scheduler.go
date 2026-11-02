package reporting

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"gomail/config"
	"gomail/logging"
	"gomail/metrics"
	"gomail/store"
)

// EnqueueFunc is a callback to enqueue a message for delivery
type EnqueueFunc func(from string, to string, message string) error

var lookupReportingTXT = net.LookupTXT

// ScheduleDailyDMARCReports sends complete UTC-day reports and catches up after downtime.
// Reports are only sent if config.dmarc.send_reports is true.
func ScheduleDailyDMARCReports(cfg *config.Config, db *store.DB, enqueueFunc EnqueueFunc) {
	if !cfg.DMARC.SendReports {
		logging.Info("[dmarc] report scheduler disabled (set dmarc.send_reports=true in config.json to enable)")
		return
	}
	logging.Info("[dmarc] report scheduler enabled (daily reports at 00:00 UTC)")
	go runDailyDMARCReportScheduler(cfg, db, enqueueFunc)
}

// ScheduleDailyTLSReports runs TLS-RPT independently for complete UTC days.
func ScheduleDailyTLSReports(cfg *config.Config, db *store.DB, enqueueFunc EnqueueFunc) {
	if !cfg.TLSRPT.SendReports {
		logging.Info("[tls-rpt] daily report scheduler disabled (set tls_rpt.send_reports=true to enable)")
		return
	}
	logging.Info("[tls-rpt] report scheduler enabled (daily at 00:00 UTC)")
	go runDailyTLSReportScheduler(cfg, db, enqueueFunc)
}

func nextUTCMidnight(now time.Time) time.Time {
	now = now.UTC()
	return time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
}

func runDailyTLSReportScheduler(cfg *config.Config, db *store.DB, enqueueFunc EnqueueFunc) {
	for {
		next := nextUTCMidnight(time.Now())
		logging.Info(fmt.Sprintf("[tls-rpt] next daily report generation: %s", next))
		time.Sleep(time.Until(next))
		generateAndSendDailyTLSReports(cfg, db, enqueueFunc, next.AddDate(0, 0, -1), next)
	}
}

func generateAndSendDailyTLSReports(cfg *config.Config, db *store.DB, enqueueFunc EnqueueFunc, startTime, endTime time.Time) {
	domains, err := db.GetDomainsWithTLSFailures()
	if err != nil {
		logging.Error(fmt.Sprintf("[tls-rpt] error getting domains with TLS events: %v", err))
		return
	}
	for _, domain := range domains {
		reportStart, eligible, startErr := db.GetTLSReportStart(domain, endTime)
		if startErr != nil {
			logging.Error(fmt.Sprintf("[tls-rpt] retry state error for %s: %v", domain, startErr))
			continue
		}
		if eligible {
			sendTLSRPTReportForDomain(cfg, db, enqueueFunc, domain, reportStart, endTime)
		}
	}
}

// SendReportsNow triggers immediate generation and delivery of DMARC reports for all domains.
// This is useful for testing without waiting for the daily scheduler.
// Returns (total_domains, successfully_reported, error).
func SendReportsNow(cfg *config.Config, db *store.DB, enqueueFunc EnqueueFunc) (int, int, error) {
	logging.Info("[dmarc] manual report generation triggered...")

	// Get all unique domains with DMARC feedback
	domains, err := db.GetDomainsWithFeedback()
	if err != nil {
		return 0, 0, fmt.Errorf("getting domains with feedback: %w", err)
	}

	if len(domains) == 0 {
		logging.Info("[dmarc] no domains with feedback to report")
		return 0, 0, nil
	}

	successCount := 0
	for _, domain := range domains {
		if sendDMARCReportForDomain(cfg, db, enqueueFunc, domain, time.Now().UTC()) {
			successCount++
		}
	}

	logging.Info(fmt.Sprintf("[dmarc] manual report generation complete (%d/%d domains reported)", successCount, len(domains)))
	return len(domains), successCount, nil
}

func runDailyDMARCReportScheduler(cfg *config.Config, db *store.DB, enqueueFunc EnqueueFunc) {
	// Process complete, unsent days left by a restart before the next midnight.
	generateAndSendReports(cfg, db, enqueueFunc)
	for {
		next := nextUTCMidnight(time.Now())
		logging.Info(fmt.Sprintf("[dmarc] next daily report generation: %s", next))
		time.Sleep(time.Until(next))

		// Generate and send reports
		generateAndSendReports(cfg, db, enqueueFunc)
	}
}

func generateAndSendReports(cfg *config.Config, db *store.DB, enqueueFunc EnqueueFunc) {
	logging.Info("[reporting] starting daily DMARC report generation...")

	// Generate DMARC reports
	dmarcDomains, err := db.GetDomainsWithFeedback()
	if err != nil {
		logging.Error(fmt.Sprintf("[dmarc] error getting domains with feedback: %v", err))
	} else if len(dmarcDomains) > 0 {
		dmarcReportCount := 0
		for _, domain := range dmarcDomains {
			if sendDMARCReportForDomain(cfg, db, enqueueFunc, domain, time.Now().UTC().Truncate(24*time.Hour)) {
				dmarcReportCount++
			}
		}
		logging.Info(fmt.Sprintf("[dmarc] daily report generation complete (%d/%d domains reported)", dmarcReportCount, len(dmarcDomains)))
	} else {
		logging.Info("[dmarc]   no domains with DMARC feedback to report")
	}

	logging.Info("[dmarc] daily reports generated")
}

func sendDMARCReportForDomain(cfg *config.Config, db *store.DB, enqueueFunc EnqueueFunc, domain *store.Domain, cutoff time.Time) bool {
	days, err := unreportedDMARCDays(db, domain.Domain, cutoff)
	if err != nil {
		logging.Error(fmt.Sprintf("[dmarc] %s: listing report days: %v", domain.Domain, err))
		return false
	}
	any := false
	for _, start := range days {
		end := start.Add(24 * time.Hour)
		if cutoff.Before(end) {
			end = cutoff
		}
		if sendDMARCReportWindow(cfg, db, enqueueFunc, domain, start, end) {
			any = true
		}
	}
	return any
}

func unreportedDMARCDays(db *store.DB, domain string, cutoff time.Time) ([]time.Time, error) {
	rows, err := db.Query(`SELECT DISTINCT SUBSTR(received_at, 1, 10) FROM dmarc_feedback WHERE COALESCE(NULLIF(policy_domain, ''), domain)=? AND sent_at IS NULL AND received_at < ? ORDER BY 1`, domain, cutoff.UTC().Format("2006-01-02 15:04:05"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var days []time.Time
	for rows.Next() {
		var day string
		if err := rows.Scan(&day); err != nil {
			return nil, err
		}
		start, err := time.Parse("2006-01-02", day)
		if err != nil {
			return nil, err
		}
		days = append(days, start.UTC())
	}
	return days, rows.Err()
}

func sendDMARCReportWindow(cfg *config.Config, db *store.DB, enqueueFunc EnqueueFunc, domain *store.Domain, start, end time.Time) bool {

	// Get DMARC policy to extract report addresses
	dmarcRecord, err := lookupDMARCForReporting(domain.Domain)
	if err != nil {
		logging.Error(fmt.Sprintf("[dmarc] %s: error looking up DMARC policy: %v", domain.Domain, err))
		return false
	}

	if dmarcRecord == nil || (len(dmarcRecord.ReportMailto) == 0 && len(dmarcRecord.ForensicMail) == 0) {
		logging.Info(fmt.Sprintf("[dmarc]  %s: no rua=/ruf= addresses configured", domain.Domain))
		return false
	}

	// Get feedback since last report until now
	records, err := getDMARCFeedbackRecords(db, domain.Domain, start, end)
	if err != nil {
		logging.Error(fmt.Sprintf("[dmarc] %s: error querying feedback: %v", domain.Domain, err))
		return false
	}

	if len(records) == 0 {
		logging.Info(fmt.Sprintf("[dmarc]  %s: no unsent feedback for %s", domain.Domain, start.Format("2006-01-02")))
		return false
	}

	// Generate XML report
	// Use our organization's domain as sender
	policy := PolicyPublished{Domain: domain.Domain, P: dmarcRecord.P, SP: dmarcRecord.SP, ADKIM: dmarcRecord.ADKIM, ASPF: dmarcRecord.ASPF, Pct: dmarcRecord.Pct}
	reportXML, err := GenerateDMARCAggregateReport(
		domain.Domain,
		fmt.Sprintf("postmaster@%s", cfg.Server.Domain),
		cfg.Server.Hostname,
		policy,
		records,
		start,
		end,
	)
	if err != nil {
		logging.Error(fmt.Sprintf("[dmarc] %s: error generating report: %v", domain.Domain, err))
		return false
	}

	// Send to rua= addresses (aggregate reports)
	sentCount := 0
	for _, reportAddr := range dmarcRecord.ReportMailto {
		targets := resolvedDMARCReportDestinations(domain.Domain, reportAddr)
		if len(targets) == 0 {
			logging.Warn(fmt.Sprintf("[dmarc] external report destination %s is not authorized for %s", reportAddr, domain.Domain))
			continue
		}
		for _, target := range targets {
			if err := sendDMARCReport(cfg, enqueueFunc, domain.Domain, cfg.Server.Domain, target, reportXML); err != nil {
				logging.Error(fmt.Sprintf("[dmarc] %s→%s: error sending report: %v", domain.Domain, target, err))
			} else {
				sentCount++
				logging.Info(fmt.Sprintf("[dmarc] %s→%s: report sent (period %s to %s, %d records)",
					domain.Domain, target,
					start.Format("2006-01-02"), end.Format("2006-01-02"),
					len(records)))
			}
		}
	}

	// Update last report time and mark feedback as sent if at least one report was sent
	if sentCount > 0 {
		metrics.IncReport("dmarc_success")
		if err := db.UpdateLastDMARCReportTime(domain.Domain); err != nil {
			logging.Error(fmt.Sprintf("[dmarc] %s: error updating last report time: %v", domain.Domain, err))
		}
		if err := db.MarkDMARCFeedbackAsSent(domain.Domain, start, end); err != nil {
			logging.Error(fmt.Sprintf("[dmarc] %s: error marking feedback as sent: %v", domain.Domain, err))
		}
	}
	if sentCount == 0 {
		metrics.IncReport("dmarc_failure")
	}

	return sentCount > 0
}

// lookupDMARCForReporting returns parsed DMARC tags with report addresses
// Similar to auth.CheckDMARC but focused on extracting rua=/ruf= values
func lookupDMARCForReporting(domain string) (*DMARCReportPolicy, error) {
	dmarcDomain := fmt.Sprintf("_dmarc.%s", domain)
	txtRecords, err := lookupReportingTXT(dmarcDomain)
	if err != nil {
		return nil, err
	}

	if len(txtRecords) == 0 {
		return nil, fmt.Errorf("no DMARC record found")
	}

	policy := &DMARCReportPolicy{}
	var selected string
	for _, txt := range txtRecords {
		if dmarcVersionRecord(txt) {
			if selected != "" {
				return nil, fmt.Errorf("multiple DMARC policy records for %s", domain)
			}
			selected = txt
		}
	}
	if selected == "" {
		return nil, fmt.Errorf("no DMARC policy record for %s", domain)
	}
	// Parse rua= and ruf= tags only after policy uniqueness is established.
	parts, err := extractDMARCTags(selected)
	if err != nil {
		return nil, err
	}
	policy.P = parts["p"]
	if policy.P != "none" && policy.P != "quarantine" && policy.P != "reject" {
		return nil, fmt.Errorf("invalid DMARC policy for %s", domain)
	}
	policy.SP = parts["sp"]
	policy.ADKIM = parts["adkim"]
	policy.ASPF = parts["aspf"]
	policy.Pct = 100
	if raw := parts["pct"]; raw != "" {
		if n, e := strconv.Atoi(raw); e == nil && n >= 0 && n <= 100 {
			policy.Pct = n
		}
	}
	if ruaVal, ok := parts["rua"]; ok {
		policy.ReportMailto = parseReportAddresses(ruaVal)
	}
	if rufVal, ok := parts["ruf"]; ok {
		policy.ForensicMail = parseReportAddresses(rufVal)
	}

	return policy, nil
}

// DMARCReportPolicy holds report recipient addresses
type DMARCReportPolicy struct {
	ReportMailto       []string
	ForensicMail       []string
	P, SP, ADKIM, ASPF string
	Pct                int
}

func authorizedDMARCReportDestination(policyDomain, address string) bool {
	return len(resolvedDMARCReportDestinations(policyDomain, address)) > 0
}

func resolvedDMARCReportDestinations(policyDomain, address string) []string {
	parsed, err := mail.ParseAddress(address)
	if err != nil {
		return nil
	}
	at := strings.LastIndex(parsed.Address, "@")
	if at < 0 {
		return nil
	}
	destination := strings.ToLower(parsed.Address[at+1:])
	if strings.EqualFold(destination, policyDomain) {
		return []string{parsed.Address}
	}
	records, err := lookupReportingTXT(policyDomain + "._report._dmarc." + destination)
	if err != nil {
		return nil
	}
	authorized := false
	var overrideTargets []string
	for _, record := range records {
		if !dmarcVersionRecord(record) {
			continue
		}
		tags, err := extractDMARCTags(record)
		if err != nil {
			continue
		}
		authorized = true
		if override, ok := tags["rua"]; ok {
			addresses := parseReportAddresses(override)
			if len(addresses) == 0 {
				return nil
			}
			canonical := make([]string, 0, len(addresses))
			for _, candidate := range addresses {
				parsedOverride, err := mail.ParseAddress(candidate)
				if err != nil {
					return nil
				}
				parts := strings.SplitN(parsedOverride.Address, "@", 2)
				if len(parts) != 2 || !strings.EqualFold(parts[1], destination) {
					return nil
				}
				canonical = append(canonical, parsedOverride.Address)
			}
			if overrideTargets != nil && !slices.Equal(overrideTargets, canonical) {
				return nil
			}
			overrideTargets = canonical
		}
	}
	if !authorized {
		return nil
	}
	if overrideTargets != nil {
		return overrideTargets
	}
	return []string{parsed.Address}
}

// extractDMARCTags parses DMARC record tags from a TXT record value
func dmarcVersionRecord(record string) bool {
	const version = "v=DMARC1"
	if !strings.HasPrefix(record, version) {
		return false
	}
	rest := strings.TrimLeft(record[len(version):], " \t")
	return rest == "" || strings.HasPrefix(rest, ";")
}

func extractDMARCTags(record string) (map[string]string, error) {
	tags := make(map[string]string)
	parts := parseTagList(record)
	for _, part := range parts {
		key, value, ok := strings.Cut(part, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid DMARC tag")
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if _, exists := tags[key]; exists {
			return nil, fmt.Errorf("duplicate DMARC tag %s", key)
		}
		tags[key] = value
	}
	if tags["v"] != "DMARC1" {
		return nil, fmt.Errorf("invalid DMARC version")
	}
	return tags, nil
}

// parseTagList splits DMARC record into tags, handling quoted values
func parseTagList(record string) []string {
	var tags []string
	var current string
	for _, c := range record {
		if c == ';' {
			if s := trim(current); len(s) > 0 {
				tags = append(tags, s)
			}
			current = ""
		} else {
			current += string(c)
		}
	}
	if s := trim(current); len(s) > 0 {
		tags = append(tags, s)
	}
	return tags
}

// parseReportAddresses extracts email addresses from rua= or ruf= tag
// Format: "mailto:addr1@example.com,mailto:addr2@example.com"
func parseReportAddresses(value string) []string {
	var addrs []string
	parts := split(value, ',')
	for _, part := range parts {
		part = trim(part)
		if len(part) > 7 && part[:7] == "mailto:" {
			addr := trim(part[7:])
			if bang := strings.LastIndex(addr, "!"); bang > strings.LastIndex(addr, "@") {
				addr = addr[:bang]
			}
			if len(addr) > 0 {
				addrs = append(addrs, addr)
			}
		}
	}
	return addrs
}

// Helper functions
func firstIndexOf(s string, c rune) int {
	for i, ch := range s {
		if ch == c {
			return i
		}
	}
	return -1
}

func split(s string, sep rune) []string {
	var parts []string
	var current string
	for _, c := range s {
		if c == sep {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	parts = append(parts, current)
	return parts
}

func trim(s string) string {
	var result string
	started := false
	for _, c := range s {
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			started = true
		}
		if started {
			result += string(c)
		}
	}
	// Trim trailing whitespace
	for len(result) > 0 && (result[len(result)-1] == ' ' || result[len(result)-1] == '\t' || result[len(result)-1] == '\n' || result[len(result)-1] == '\r') {
		result = result[:len(result)-1]
	}
	return result
}

// getLastSunday returns the last Sunday at 00:00 UTC
// If today is Sunday, returns today; otherwise returns the previous Sunday
func getLastSunday(t time.Time) time.Time {
	t = t.UTC()
	daysBack := int(t.Weekday())
	if daysBack == 0 { // Already Sunday
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	}
	lastSunday := t.AddDate(0, 0, -daysBack)
	return time.Date(lastSunday.Year(), lastSunday.Month(), lastSunday.Day(), 0, 0, 0, 0, time.UTC)
}

func getDMARCFeedbackRecords(db *store.DB, domain string, startTime, endTime time.Time) ([]ReportRecord, error) {
	rows, err := db.Query(`
		SELECT domain, source_ip, COUNT(*) as count, COALESCE(dkim_result, 'none'),
		       COALESCE(dkim_domain, ''), COALESCE(dkim_selector, ''),
		       COALESCE(spf_result, 'none'), COALESCE(spf_domain, envelope_from_domain, ''),
		       COALESCE(spf_scope, 'mfrom'), COALESCE(disposition, 'none'),
		       COALESCE(envelope_from_domain, ''), dkim_aligned, spf_aligned
		FROM dmarc_feedback
		WHERE COALESCE(NULLIF(policy_domain, ''), domain) = ? AND received_at >= ? AND received_at < ? AND sent_at IS NULL
		GROUP BY domain, source_ip, dkim_result, dkim_domain, dkim_selector,
		         spf_result, spf_domain, spf_scope, disposition, envelope_from_domain,
		         dkim_aligned, spf_aligned
		ORDER BY count DESC
	`, domain, startTime.UTC().Format("2006-01-02 15:04:05"), endTime.UTC().Format("2006-01-02 15:04:05"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []ReportRecord
	for rows.Next() {
		var headerFrom, sourceIP string
		var count int
		var dkimAligned, spfAligned bool
		var dkimResult, dkimDomain, dkimSelector string
		var spfResult, spfDomain, spfScope string
		var disposition, envelopeDomain string

		if err := rows.Scan(&headerFrom, &sourceIP, &count, &dkimResult, &dkimDomain, &dkimSelector,
			&spfResult, &spfDomain, &spfScope, &disposition, &envelopeDomain, &dkimAligned, &spfAligned); err != nil {
			logging.Error(fmt.Sprintf("[dmarc] error scanning feedback: %v", err))
			continue
		}

		record := ReportRecord{
			Row: Row{
				SourceIP: sourceIP,
				Count:    count,
				PolicyEval: PolicyEvaluated{
					Disposition: disposition,
					DKIM:        alignmentResult(dkimAligned),
					SPF:         alignmentResult(spfAligned),
				},
			},
			Identifiers: Identifiers{
				HeaderFrom:   headerFrom,
				EnvelopeFrom: envelopeDomain,
			},
			AuthResults: AuthResults{
				DKIM: []DKIMAuthResult{{Domain: dkimDomain, Result: dkimResult, Selector: dkimSelector}},
				SPF:  []SPFAuthResult{{Domain: spfDomain, Result: spfResult, Scope: spfScope}},
			},
		}

		records = append(records, record)
	}

	return records, rows.Err()
}

func alignmentResult(aligned bool) string {
	if aligned {
		return "pass"
	}
	return "fail"
}

func dkimResultToString(pass, total int) string {
	if pass == total {
		return "pass"
	}
	if pass == 0 {
		return "fail"
	}
	return "neutral"
}

func spfResultToString(pass, total int) string {
	if pass == total {
		return "pass"
	}
	if pass == 0 {
		return "fail"
	}
	return "neutral"
}

func sendDMARCReport(cfg *config.Config, enqueueFunc EnqueueFunc, reportedDomain, senderDomain, toAddr, reportXML string) error {
	report, err := ParseDMARCReport(strings.NewReader(reportXML))
	if err != nil {
		return fmt.Errorf("reading generated DMARC report metadata: %w", err)
	}
	if report.Metadata.ReportID == "" || report.Metadata.DateRange.Begin >= report.Metadata.DateRange.End {
		return fmt.Errorf("generated DMARC report has invalid identity or date range")
	}
	filename := fmt.Sprintf("%s!%s!%d!%d.xml.gz", cfg.Server.Hostname, reportedDomain,
		report.Metadata.DateRange.Begin, report.Metadata.DateRange.End)

	// RFC 9990: gzip the XML and fold base64 to MIME's 76-character lines.
	var compressedBuf bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressedBuf)
	if _, err := gzipWriter.Write([]byte(reportXML)); err != nil {
		return err
	}
	if err := gzipWriter.Close(); err != nil {
		return err
	}

	xmlB64 := base64.StdEncoding.EncodeToString(compressedBuf.Bytes())
	var folded strings.Builder
	for len(xmlB64) > 76 {
		folded.WriteString(xmlB64[:76])
		folded.WriteString("\r\n")
		xmlB64 = xmlB64[76:]
	}
	folded.WriteString(xmlB64)

	messageBody := fmt.Sprintf(
		"From: postmaster@%s\r\n"+
			"To: %s\r\n"+
			"Subject: Report Domain: %s Submitter: %s Report-ID: <%s>\r\n"+
			"Message-ID: <%s>\r\n"+
			"Date: %s\r\n"+
			"Content-Type: multipart/mixed; boundary=\"boundary123\"\r\n"+
			"MIME-Version: 1.0\r\n"+
			"\r\n"+
			"--boundary123\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Transfer-Encoding: 7bit\r\n"+
			"\r\n"+
			"This is the DMARC aggregate report for %s.\r\n"+
			"\r\n"+
			"--boundary123\r\n"+
			"Content-Type: application/gzip; name=\"%s\"\r\n"+
			"Content-Transfer-Encoding: base64\r\n"+
			"Content-Disposition: attachment; filename=\"%s\"\r\n"+
			"\r\n"+
			"%s\r\n"+
			"--boundary123--\r\n",
		senderDomain,
		toAddr,
		reportedDomain,
		cfg.Server.Hostname,
		report.Metadata.ReportID,
		report.Metadata.ReportID,
		time.Now().Format(time.RFC1123Z),
		reportedDomain,
		filename,
		filename,
		folded.String(),
	)

	return enqueueFunc(fmt.Sprintf("postmaster@%s", senderDomain), toAddr, messageBody)
}

// sendTLSRPTReportForDomain generates and sends a TLS-RPT report for a domain
func sendTLSRPTReportForDomain(cfg *config.Config, db *store.DB, enqueueFunc EnqueueFunc, domain string, startTime, endTime time.Time) bool {
	// Generate the report
	report, err := GenerateTLSReport(db, cfg.Server.Domain, domain, startTime, endTime)
	if err != nil {
		logging.Error(fmt.Sprintf("[tls-rpt] failed to generate report for %s: %v", domain, err))
		return false
	}

	// Extract TLS-RPT report addresses from DNS (may be multiple)
	destinations, err := ExtractTLSRPTURIs(domain)
	if err != nil {
		logging.Error(fmt.Sprintf("[tls-rpt] failed to extract TLS-RPT addresses for %s: %v", domain, err))
		_ = db.RecordTLSReportFailure(domain, startTime, endTime, err)
		return false
	}

	// Show a dedicated report sender while routing transport failures to
	// postmaster (the contact-info address in the JSON report).
	senderEmail := cfg.Server.TLSReportSenderAddress()
	envelopeSender := fmt.Sprintf("postmaster@%s", cfg.Server.Domain)
	// Send to each recipient address
	sentCount := 0
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 || request.URL.Scheme != "https" {
			return fmt.Errorf("unsafe TLS-RPT redirect")
		}
		return nil
	}}
	for _, destination := range destinations {
		parsed, _ := url.Parse(destination)
		var sendErr error
		if parsed.Scheme == "mailto" {
			messageBody := BuildTLSRPTEmail(cfg.Server.Domain, senderEmail, report, parsed.Opaque)
			sendErr = enqueueFunc(envelopeSender, parsed.Opaque, messageBody)
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			sendErr = PostTLSRPT(ctx, client, destination, report)
			cancel()
		}
		if sendErr != nil {
			logging.Error(fmt.Sprintf("[tls-rpt] delivery failed for %s -> %s: %v", domain, destination, sendErr))
			continue
		}
		sentCount++
		logging.Info(fmt.Sprintf("[tls-rpt] report accepted for %s -> %s", domain, destination))
	}

	if sentCount == 0 {
		metrics.IncReport("tlsrpt_failure")
		logging.Warn(fmt.Sprintf("[tls-rpt] failed to queue TLS-RPT report for %s to any recipient", domain))
		_ = db.RecordTLSReportFailure(domain, startTime, endTime, fmt.Errorf("all TLS-RPT destinations failed"))
		return false
	}
	metrics.IncReport("tlsrpt_success")

	// Mark failures as reported
	if err := db.MarkTLSFailuresAsReported(domain, startTime, endTime); err != nil {
		logging.Warn(fmt.Sprintf("[tls-rpt] warning: failed to mark TLS failures as reported for %s: %v", domain, err))
		// Non-fatal error, report was sent successfully
	}

	totalFailures := 0
	for _, policy := range report.Policies {
		totalFailures += policy.Summary.TotalFailureSessionCount
	}
	logging.Info(fmt.Sprintf("[tls-rpt] generated and queued TLS-RPT report for %s (%d recipients, %d failures)",
		domain, sentCount, totalFailures))
	return true
}
