package reporting

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"time"

	"gomail/config"
	"gomail/store"
)

// EnqueueFunc is a callback to enqueue a message for delivery
type EnqueueFunc func(from string, to string, message string) error

// ScheduleWeeklyReports starts a background job to generate and send DMARC reports weekly.
// Reports are only sent if config.dmarc.send_reports is true.
func ScheduleWeeklyReports(cfg *config.Config, db *store.DB, enqueueFunc EnqueueFunc) {
	if !cfg.DMARC.SendReports {
		log.Printf("[dmarc] ℹ️  report scheduler disabled (set dmarc.send_reports=true in config.json to enable)")
		return
	}
	log.Printf("[dmarc] report scheduler enabled (weekly reports at Sunday 00:00 UTC)")
	go runWeeklyReportScheduler(cfg, db, enqueueFunc)
}

// SendReportsNow triggers immediate generation and delivery of DMARC reports for all domains.
// This is useful for testing without waiting for the weekly scheduler.
// Returns (total_domains, successfully_reported, error).
func SendReportsNow(cfg *config.Config, db *store.DB, enqueueFunc EnqueueFunc) (int, int, error) {
	log.Printf("[dmarc] manual report generation triggered...")

	// Get all unique domains with DMARC feedback
	domains, err := db.GetDomainsWithFeedback()
	if err != nil {
		return 0, 0, fmt.Errorf("getting domains with feedback: %w", err)
	}

	if len(domains) == 0 {
		log.Printf("[dmarc] no domains with feedback to report")
		return 0, 0, nil
	}

	successCount := 0
	for _, domain := range domains {
		if sendReportForDomain(cfg, db, enqueueFunc, domain) {
			successCount++
		}
	}

	log.Printf("[dmarc] ✅ manual report generation complete (%d/%d domains reported)", successCount, len(domains))
	return len(domains), successCount, nil
}

func runWeeklyReportScheduler(cfg *config.Config, db *store.DB, enqueueFunc EnqueueFunc) {
	for {
		// Calculate time until next Sunday at 00:00 UTC
		now := time.Now().UTC()
		nextSunday := now.AddDate(0, 0, 1)
		for nextSunday.Weekday() != time.Sunday {
			nextSunday = nextSunday.AddDate(0, 0, 1)
		}
		nextSunday = time.Date(nextSunday.Year(), nextSunday.Month(), nextSunday.Day(), 0, 0, 0, 0, time.UTC)

		waitTime := nextSunday.Sub(now)
		log.Printf("[dmarc] next weekly report generation: %s (in %v)", nextSunday, waitTime)
		time.Sleep(waitTime)

		// Generate and send reports
		generateAndSendReports(cfg, db, enqueueFunc)
	}
}

func generateAndSendReports(cfg *config.Config, db *store.DB, enqueueFunc EnqueueFunc) {
	log.Printf("[dmarc] starting weekly report generation...")

	// Get all unique domains with DMARC feedback
	domains, err := db.GetDomainsWithFeedback()
	if err != nil {
		log.Printf("[dmarc] ❌ error getting domains with feedback: %v", err)
		return
	}

	if len(domains) == 0 {
		log.Printf("[dmarc] ℹ️  no domains with feedback to report")
		return
	}

	reportCount := 0
	for _, domain := range domains {
		if sendReportForDomain(cfg, db, enqueueFunc, domain) {
			reportCount++
		}
	}

	log.Printf("[dmarc] ✅ weekly report generation complete (%d/%d domains reported)", reportCount, len(domains))
}

func sendReportForDomain(cfg *config.Config, db *store.DB, enqueueFunc EnqueueFunc, domain *store.Domain) bool {
	// Get the time of the last successful report for this domain
	// If never reported, this returns epoch time (Jan 1, 1970)
	lastReportTime, err := db.GetLastDMARCReportTime(domain.Domain)
	if err != nil {
		log.Printf("[dmarc] ❌ %s: error getting last report time: %v", domain.Domain, err)
		return false
	}

	now := time.Now().UTC()

	// Get DMARC policy to extract report addresses
	dmarcRecord, err := lookupDMARCForReporting(domain.Domain)
	if err != nil {
		log.Printf("[dmarc] ❌ %s: error looking up DMARC policy: %v", domain.Domain, err)
		return false
	}

	if dmarcRecord == nil || (len(dmarcRecord.ReportMailto) == 0 && len(dmarcRecord.ForensicMail) == 0) {
		log.Printf("[dmarc] ℹ️  %s: no rua=/ruf= addresses configured", domain.Domain)
		return false
	}

	// Get feedback since last report until now
	records, err := getDMARCFeedbackRecords(db, domain.Domain, lastReportTime, now)
	if err != nil {
		log.Printf("[dmarc] ❌ %s: error querying feedback: %v", domain.Domain, err)
		return false
	}

	if len(records) == 0 {
		log.Printf("[dmarc] ℹ️  %s: no feedback since last report (%s)",
			domain.Domain, lastReportTime.Format("2006-01-02 15:04:05 UTC"))
		return false
	}

	// Generate XML report
	// Use server's own domain as sender (not the DMARC domain being reported)
	policy := PolicyPublished{Domain: domain.Domain, P: "none"}
	reportXML, err := GenerateDMARCAggregateReport(
		domain.Domain,
		fmt.Sprintf("postmaster@%s", cfg.Server.Hostname),
		cfg.Server.Hostname,
		policy,
		records,
		lastReportTime,
		now,
	)
	if err != nil {
		log.Printf("[dmarc] ❌ %s: error generating report: %v", domain.Domain, err)
		return false
	}

	// Send to rua= addresses (aggregate reports)
	sentCount := 0
	for _, reportAddr := range dmarcRecord.ReportMailto {
		if err := sendDMARCReport(cfg, enqueueFunc, domain.Domain, cfg.Server.Hostname, reportAddr, reportXML); err != nil {
			log.Printf("[dmarc] ❌ %s→%s: error sending report: %v", domain.Domain, reportAddr, err)
		} else {
			sentCount++
			log.Printf("[dmarc] ✅ %s→%s: report sent (period %s to %s, %d records)",
				domain.Domain, reportAddr,
				lastReportTime.Format("2006-01-02"), now.Format("2006-01-02"),
				len(records))
		}
	}

	// Update last report time and mark feedback as sent if at least one report was sent
	if sentCount > 0 {
		if err := db.UpdateLastDMARCReportTime(domain.Domain); err != nil {
			log.Printf("[dmarc] ⚠️  %s: error updating last report time: %v", domain.Domain, err)
		}
		if err := db.MarkDMARCFeedbackAsSent(domain.Domain, lastReportTime, now); err != nil {
			log.Printf("[dmarc] ⚠️  %s: error marking feedback as sent: %v", domain.Domain, err)
		}
	}

	return sentCount > 0
}

// lookupDMARCForReporting returns parsed DMARC tags with report addresses
// Similar to auth.CheckDMARC but focused on extracting rua=/ruf= values
func lookupDMARCForReporting(domain string) (*DMARCReportPolicy, error) {
	dmarcDomain := fmt.Sprintf("_dmarc.%s", domain)
	txtRecords, err := net.LookupTXT(dmarcDomain)
	if err != nil {
		return nil, err
	}

	if len(txtRecords) == 0 {
		return nil, fmt.Errorf("no DMARC record found")
	}

	policy := &DMARCReportPolicy{}
	for _, txt := range txtRecords {
		if len(txt) > 0 && txt[0] == 'v' && txt == "v=DMARC1" || (len(txt) > 8 && txt[:8] == "v=DMARC1") {
			// Parse rua= and ruf= tags
			parts := extractDMARCTags(txt)
			if ruaVal, ok := parts["rua"]; ok {
				policy.ReportMailto = parseReportAddresses(ruaVal)
			}
			if rufVal, ok := parts["ruf"]; ok {
				policy.ForensicMail = parseReportAddresses(rufVal)
			}
			break
		}
	}

	return policy, nil
}

// DMARCReportPolicy holds report recipient addresses
type DMARCReportPolicy struct {
	ReportMailto []string
	ForensicMail []string
}

// extractDMARCTags parses DMARC record tags from a TXT record value
func extractDMARCTags(record string) map[string]string {
	tags := make(map[string]string)
	parts := parseTagList(record)
	for _, part := range parts {
		if idx := firstIndexOf(part, '='); idx >= 0 {
			key := part[:idx]
			value := part[idx+1:]
			tags[key] = value
		}
	}
	return tags
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
		SELECT source_ip, COUNT(*) as count,
		       SUM(CASE WHEN dkim_result = 'pass' THEN 1 ELSE 0 END) as dkim_pass,
		       SUM(CASE WHEN spf_result = 'pass' THEN 1 ELSE 0 END) as spf_pass,
		       disposition, envelope_from_domain
		FROM dmarc_feedback
		WHERE domain = ? AND received_at >= datetime(?) AND received_at < datetime(?) AND sent_at IS NULL
		GROUP BY source_ip, disposition
		ORDER BY count DESC
	`, domain, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []ReportRecord
	for rows.Next() {
		var sourceIP string
		var count, dkimPass, spfPass int
		var disposition, envelopeDomain string

		if err := rows.Scan(&sourceIP, &count, &dkimPass, &spfPass, &disposition, &envelopeDomain); err != nil {
			log.Printf("[dmarc] error scanning feedback: %v", err)
			continue
		}

		record := ReportRecord{
			Row: Row{
				SourceIP: sourceIP,
				Count:    count,
				PolicyEval: PolicyEvaluated{
					Disposition: disposition,
					DKIM:        dkimResultToString(dkimPass, count),
					SPF:         spfResultToString(spfPass, count),
				},
			},
			Identifiers: Identifiers{
				HeaderFrom:   domain,
				EnvelopeFrom: envelopeDomain,
			},
		}

		records = append(records, record)
	}

	return records, rows.Err()
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
	reportID := fmt.Sprintf("%d@%s", time.Now().Unix(), reportedDomain)

	// Base64 encode the XML report
	xmlB64 := base64.StdEncoding.EncodeToString([]byte(reportXML))

	messageBody := fmt.Sprintf(`From: postmaster@%s
To: %s
Subject: DMARC Report for %s
Message-ID: <%s>
Date: %s
Content-Type: multipart/mixed; boundary="boundary123"
MIME-Version: 1.0

--boundary123
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

This is the DMARC aggregate report for %s.

--boundary123
Content-Type: application/xml; name="report.xml"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="report.xml"

%s

--boundary123--
`,
		senderDomain,
		toAddr,
		reportedDomain,
		reportID,
		time.Now().Format(time.RFC1123Z),
		reportedDomain,
		xmlB64,
	)

	return enqueueFunc(fmt.Sprintf("postmaster@%s", senderDomain), toAddr, messageBody)
}
