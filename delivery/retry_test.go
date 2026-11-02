package delivery

import (
	"testing"
	"time"

	"gomail/config"
)

func TestRetryScheduleUsesFirstConfiguredInterval(t *testing.T) {
	schedule := NewRetrySchedule([]int{10, 20, 30})
	for _, tc := range []struct{ attempt, seconds int }{
		{1, 10}, {2, 20}, {3, 30}, {4, 60},
	} {
		before := time.Now()
		next := schedule.NextRetry(tc.attempt)
		if next.Before(before.Add(time.Duration(tc.seconds)*time.Second)) || next.After(time.Now().Add(time.Duration(tc.seconds)*time.Second+time.Second)) {
			t.Fatalf("attempt %d: retry at %s, expected delay %ds", tc.attempt, next, tc.seconds)
		}
	}
}

func TestDefaultRetryLifetimeExceedsFiveDays(t *testing.T) {
	cfg := &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test"}, TLS: config.TLSConfig{Mode: "none"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Delivery.MaxRetries != len(cfg.Delivery.RetryIntervals)+1 {
		t.Fatalf("attempts=%d intervals=%d", cfg.Delivery.MaxRetries, len(cfg.Delivery.RetryIntervals))
	}
	var lifetime time.Duration
	for _, delay := range cfg.Delivery.RetryIntervals {
		lifetime += time.Duration(delay) * time.Second
	}
	if lifetime < 5*24*time.Hour {
		t.Fatalf("default temporary-failure lifetime is only %s", lifetime)
	}
}

func TestRetryScheduleNeverOverflowsIntoImmediateRetry(t *testing.T) {
	schedule := NewRetrySchedule([]int{31557600})
	before := time.Now().UTC()
	next := schedule.NextRetry(1_000_000)
	if next.Before(before.Add(48*time.Hour)) || next.After(time.Now().UTC().Add(48*time.Hour+time.Second)) {
		t.Fatalf("overflowed retry schedule: %s", next)
	}
	if got := NewRetrySchedule(nil).NextRetry(1); got.Before(time.Now().Add(29 * time.Minute)) {
		t.Fatalf("empty schedule did not delay retry: %s", got)
	}
}

func TestConfigRejectsNonPositiveRetryIntervals(t *testing.T) {
	for _, intervals := range [][]int{{-1}, {30, 0}, {31557601}} {
		cfg := &config.Config{Server: config.ServerConfig{Hostname: "mail.example.test"}, TLS: config.TLSConfig{Mode: "none"}}
		cfg.Delivery.RetryIntervals = intervals
		if err := cfg.Validate(); err == nil {
			t.Fatalf("accepted invalid retry intervals %v", intervals)
		}
	}
}
