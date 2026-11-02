package metrics

import "sync"

var counters = struct {
	sync.RWMutex
	values map[string]map[string]uint64
}{values: map[string]map[string]uint64{}}

var allowedLabels = map[string]map[string]bool{
	"smtp_messages_total":             labelSet("accepted", "deferred", "rejected"),
	"login_events_total":              labelSet("failed", "blocked"),
	"delivery_attempts_total":         labelSet("delivered", "retry", "failed", "state_error"),
	"report_delivery_total":           labelSet("dmarc_success", "dmarc_failure", "tlsrpt_success", "tlsrpt_failure"),
	"dane_dnssec_total":               labelSet("authenticated", "insecure", "no_record", "malformed", "lookup_error", "matched", "mismatch"),
	"quota_rejections_total":          labelSet("inbound", "submission", "webmail", "forward", "delivery", "draft"),
	"outbound_limit_rejections_total": labelSet("submission", "webmail", "forward"),
}

func labelSet(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func increment(name, label string) {
	if !allowedLabels[name][label] {
		return
	}
	counters.Lock()
	defer counters.Unlock()
	if counters.values[name] == nil {
		counters.values[name] = map[string]uint64{}
	}
	counters.values[name][label]++
}

func counterSnapshot() map[string]map[string]uint64 {
	counters.RLock()
	defer counters.RUnlock()
	result := make(map[string]map[string]uint64, len(allowedLabels))
	for name, labels := range allowedLabels {
		result[name] = make(map[string]uint64, len(labels))
		for label := range labels {
			result[name][label] = counters.values[name][label]
		}
	}
	return result
}

func IncSMTP(outcome string)          { increment("smtp_messages_total", outcome) }
func IncLogin(outcome string)         { increment("login_events_total", outcome) }
func IncDelivery(outcome string)      { increment("delivery_attempts_total", outcome) }
func IncReport(outcome string)        { increment("report_delivery_total", outcome) }
func IncDANE(outcome string)          { increment("dane_dnssec_total", outcome) }
func IncQuota(context string)         { increment("quota_rejections_total", context) }
func IncOutboundLimit(context string) { increment("outbound_limit_rejections_total", context) }
