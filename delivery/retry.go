package delivery

import (
	"math"
	"time"
)

// RetrySchedule calculates the next retry time based on the attempt number
// and configured retry intervals.
type RetrySchedule struct {
	Intervals []int // Retry delay in seconds for each attempt
}

// NewRetrySchedule creates a retry schedule from config.
func NewRetrySchedule(intervals []int) *RetrySchedule {
	return &RetrySchedule{Intervals: intervals}
}

// NextRetry returns the time for the next delivery attempt.
// If attempt exceeds the configured intervals, uses exponential backoff
// based on the last interval.
func (r *RetrySchedule) NextRetry(attempt int) time.Time {
	var delaySec int

	if attempt < len(r.Intervals) {
		delaySec = r.Intervals[attempt]
	} else {
		// Exponential backoff from last interval
		lastInterval := r.Intervals[len(r.Intervals)-1]
		extra := attempt - len(r.Intervals) + 1
		delaySec = lastInterval * int(math.Pow(2, float64(extra)))
		// Cap at 48 hours
		if delaySec > 172800 {
			delaySec = 172800
		}
	}

	return time.Now().Add(time.Duration(delaySec) * time.Second)
}
