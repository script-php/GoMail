package reporting

import (
	"encoding/xml"
	"fmt"
	"io"
	"time"
)

// DMARCReport represents a DMARC aggregate report (RFC 7489).
type DMARCReport struct {
	XMLName  xml.Name        `xml:"feedback"`
	Metadata ReportMetadata  `xml:"report_metadata"`
	Policy   PolicyPublished `xml:"policy_published"`
	Records  []ReportRecord  `xml:"record"`
}

type ReportMetadata struct {
	OrgName   string    `xml:"org_name"`
	Email     string    `xml:"email"`
	ReportID  string    `xml:"report_id"`
	DateRange DateRange `xml:"date_range"`
}

type DateRange struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
}

type PolicyPublished struct {
	Domain string `xml:"domain"`
	ADKIM  string `xml:"adkim"`
	ASPF   string `xml:"aspf"`
	P      string `xml:"p"`
	SP     string `xml:"sp"`
	Pct    int    `xml:"pct"`
}

type ReportRecord struct {
	Row         Row         `xml:"row"`
	Identifiers Identifiers `xml:"identifiers"`
	AuthResults AuthResults `xml:"auth_results"`
}

type Row struct {
	SourceIP   string          `xml:"source_ip"`
	Count      int             `xml:"count"`
	PolicyEval PolicyEvaluated `xml:"policy_evaluated"`
}

type PolicyEvaluated struct {
	Disposition string `xml:"disposition"`
	DKIM        string `xml:"dkim"`
	SPF         string `xml:"spf"`
}

type Identifiers struct {
	HeaderFrom   string `xml:"header_from"`
	EnvelopeFrom string `xml:"envelope_from"`
}

type AuthResults struct {
	DKIM []DKIMAuthResult `xml:"dkim"`
	SPF  []SPFAuthResult  `xml:"spf"`
}

type DKIMAuthResult struct {
	Domain   string `xml:"domain"`
	Result   string `xml:"result"`
	Selector string `xml:"selector"`
}

type SPFAuthResult struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
}

// ParseDMARCReport parses a DMARC aggregate report from XML.
func ParseDMARCReport(r io.Reader) (*DMARCReport, error) {
	var report DMARCReport
	if err := xml.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("parsing DMARC report: %w", err)
	}
	return &report, nil
}

// GenerateDMARCAggregateReport generates an RFC 7489-compliant DMARC aggregate report.
func GenerateDMARCAggregateReport(
	domain string,
	reporterEmail string,
	reporterOrg string,
	policy PolicyPublished,
	records []ReportRecord,
	startTime, endTime time.Time,
) (string, error) {
	reportID := fmt.Sprintf("%d.%d.%s@%s",
		startTime.Unix(),
		endTime.Unix(),
		domain,
		reporterOrg,
	)

	report := DMARCReport{
		XMLName: xml.Name{Local: "feedback"},
		Metadata: ReportMetadata{
			OrgName:  reporterOrg,
			Email:    reporterEmail,
			ReportID: reportID,
			DateRange: DateRange{
				Begin: startTime.Unix(),
				End:   endTime.Unix(),
			},
		},
		Policy:  policy,
		Records: records,
	}

	// Marshal to XML with proper declaration
	output, err := xml.MarshalIndent(&report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling DMARC report: %w", err)
	}

	// Add XML declaration
	return fmt.Sprintf("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n%s\n", string(output)), nil
}
