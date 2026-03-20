package smtp

import (
	"sync"
	"time"
)

// RateLimiter provides per-IP connection and message rate limiting.
type RateLimiter struct {
	mu          sync.Mutex
	connections map[string]*rateWindow
	messages    map[string]*rateWindow

	maxConnsPerMin int
	maxMsgsPerMin  int
}

type rateWindow struct {
	timestamps []time.Time
}

// NewRateLimiter creates a rate limiter with the given per-minute limits.
func NewRateLimiter(connsPerMin, msgsPerMin int) *RateLimiter {
	rl := &RateLimiter{
		connections:    make(map[string]*rateWindow),
		messages:       make(map[string]*rateWindow),
		maxConnsPerMin: connsPerMin,
		maxMsgsPerMin:  msgsPerMin,
	}
	// Start cleanup goroutine
	go rl.cleanup()
	return rl
}

// AllowConnection checks if a new connection from this IP is allowed.
func (rl *RateLimiter) AllowConnection(ip string) bool {
	return rl.allow(rl.connections, ip, rl.maxConnsPerMin)
}

// AllowMessage checks if a new message from this IP is allowed.
func (rl *RateLimiter) AllowMessage(ip string) bool {
	return rl.allow(rl.messages, ip, rl.maxMsgsPerMin)
}

func (rl *RateLimiter) allow(windows map[string]*rateWindow, ip string, limit int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Minute)

	w, ok := windows[ip]
	if !ok {
		w = &rateWindow{}
		windows[ip] = w
	}

	// Prune old timestamps
	valid := w.timestamps[:0]
	for _, t := range w.timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	w.timestamps = valid

	if len(w.timestamps) >= limit {
		return false
	}

	w.timestamps = append(w.timestamps, now)
	return true
}

// cleanup periodically removes stale entries.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-time.Minute)
		cleanMap(rl.connections, cutoff)
		cleanMap(rl.messages, cutoff)
		rl.mu.Unlock()
	}
}

func cleanMap(m map[string]*rateWindow, cutoff time.Time) {
	for ip, w := range m {
		valid := w.timestamps[:0]
		for _, t := range w.timestamps {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(m, ip)
		} else {
			w.timestamps = valid
		}
	}
}
