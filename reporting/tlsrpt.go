package reporting

import (
	"encoding/json"
	"fmt"
	"io"
)

// TLSReport represents a TLS-RPT report (RFC 8460).
type TLSReport struct {
	OrganizationName string      `json:"organization-name"`
	DateRange        TLSDateRange `json:"date-range"`
	ContactInfo      string      `json:"contact-info"`
	ReportID         string      `json:"report-id"`
	Policies         []TLSPolicy `json:"policies"`
}

type TLSDateRange struct {
	StartDatetime string `json:"start-datetime"`
	EndDatetime   string `json:"end-datetime"`
}

type TLSPolicy struct {
	Policy  TLSPolicyDesc   `json:"policy"`
	Summary TLSPolicySummary `json:"summary"`
	FailureDetails []TLSFailure `json:"failure-details,omitempty"`
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
