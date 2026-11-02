package delivery

import "time"

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
	index := attempt - 1 // Attempt 1 is the initial failure and first retry delay.
	if index < 0 {
		index = 0
	}
	if len(r.Intervals) == 0 {
		delaySec = 1800
	} else if index < len(r.Intervals) {
		delaySec = r.Intervals[index]
	} else {
		// Saturating integer backoff avoids floating-point overflow for
		// unusually large attempt numbers.
		delaySec = r.Intervals[len(r.Intervals)-1]
		extra := index - len(r.Intervals) + 1
		for extra > 0 && delaySec < 172800 {
			if delaySec > 86400 {
				delaySec = 172800
			} else {
				delaySec *= 2
			}
			extra--
		}
		if delaySec > 172800 {
			delaySec = 172800
		}
	}
	if delaySec <= 0 {
		delaySec = 1800
	}

	return time.Now().UTC().Add(time.Duration(delaySec) * time.Second)
}
