package web

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HTTPSRedirect returns a handler that redirects HTTP to HTTPS.
func HTTPSRedirect(httpsPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		// Strip port if present
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			host = host[:idx]
		}
		target := "https://" + host
		if httpsPort != ":443" && httpsPort != "" {
			target += httpsPort
		}
		target += r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

// WebRateLimiter provides rate limiting for web requests.
type WebRateLimiter struct {
	mu      sync.Mutex
	clients map[string]*webRateEntry
	limit   int
	window  time.Duration
}

type webRateEntry struct {
	count   int
	resetAt time.Time
}

// NewWebRateLimiter creates a rate limiter for HTTP requests.
func NewWebRateLimiter(requestsPerMinute int) *WebRateLimiter {
	rl := &WebRateLimiter{
		clients: make(map[string]*webRateEntry),
		limit:   requestsPerMinute,
		window:  time.Minute,
	}
	go rl.cleanup()
	return rl
}

// Middleware wraps a handler with rate limiting (excludes static files).
func (rl *WebRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting for static assets (CSS, JS, images, fonts)
		if strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}

		ip := extractIP(r)

		rl.mu.Lock()
		entry, ok := rl.clients[ip]
		now := time.Now()

		if !ok || now.After(entry.resetAt) {
			rl.clients[ip] = &webRateEntry{count: 1, resetAt: now.Add(rl.window)}
			rl.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}

		entry.count++
		if entry.count > rl.limit {
			rl.mu.Unlock()
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		rl.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}

func (rl *WebRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, entry := range rl.clients {
			if now.After(entry.resetAt) {
				delete(rl.clients, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func extractIP(r *http.Request) string {
	// Check X-Forwarded-For first (if behind reverse proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// LoginRateLimiter tracks failed login attempts per IP (prevents brute-force attacks without blocking legitimate users).
type LoginRateLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempt // key is IP address
	maxFails int                      // After this many fails from same IP, lock the IP
	lockTime time.Duration            // How long to lock the IP
}

type loginAttempt struct {
	count        int
	lastAttempt  time.Time
	blockedUntil time.Time
}

// NewLoginRateLimiter creates a login rate limiter (5 fails/ IP locks for 15 minutes).
func NewLoginRateLimiter() *LoginRateLimiter {
	lr := &LoginRateLimiter{
		attempts: make(map[string]*loginAttempt),
		maxFails: 5,
		lockTime: 15 * time.Minute,
	}
	go lr.cleanup()
	return lr
}

// RecordFailure marks a failed login attempt from an IP.
func (lr *LoginRateLimiter) RecordFailure(ip string) {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	now := time.Now()
	entry, ok := lr.attempts[ip]

	if !ok {
		// First attempt from this IP
		lr.attempts[ip] = &loginAttempt{
			count:        1,
			lastAttempt:  now,
			blockedUntil: time.Time{}, // Not blocked
		}
		log.Printf("[web] [rate-limit] login failure 1/5 from IP %s", ip)
		return
	}

	// If block has expired, reset the counter
	if now.After(entry.blockedUntil) && !entry.blockedUntil.IsZero() {
		lr.attempts[ip] = &loginAttempt{
			count:        1,
			lastAttempt:  now,
			blockedUntil: time.Time{},
		}
		log.Printf("[web] [rate-limit] block expired for IP %s, reset counter to 1", ip)
		return
	}

	entry.count++
	entry.lastAttempt = now

	log.Printf("[web] [rate-limit] login failure %d/5 from IP %s", entry.count, ip)

	if entry.count >= lr.maxFails {
		entry.blockedUntil = now.Add(lr.lockTime)
		log.Printf("[web] [rate-limit] IP %s BLOCKED after %d failed login attempts (unlock at %v)", ip, entry.count, entry.blockedUntil)
	}
}

// RecordSuccess clears failures for an IP on successful login.
func (lr *LoginRateLimiter) RecordSuccess(ip string) {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	delete(lr.attempts, ip)
}

// IsBlocked checks if an IP is currently blocked and returns remaining block time.
func (lr *LoginRateLimiter) IsBlocked(ip string) (bool, time.Duration) {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	entry, ok := lr.attempts[ip]
	if !ok {
		return false, 0
	}

	now := time.Now()
	if now.Before(entry.blockedUntil) {
		remaining := entry.blockedUntil.Sub(now)
		log.Printf("[web] [rate-limit] IP %s is blocked, remaining=%v", ip, remaining)
		return true, remaining
	}

	return false, 0
}

// cleanup periodically removes old entries.
func (lr *LoginRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		lr.mu.Lock()
		now := time.Now()
		for ip, entry := range lr.attempts {
			// Remove if no recent attempts and block expired
			if now.After(entry.lastAttempt.Add(30*time.Minute)) && now.After(entry.blockedUntil) {
				delete(lr.attempts, ip)
			}
		}
		lr.mu.Unlock()
	}
}

// LogRequest logs HTTP requests.
func LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &loggingResponseWriter{ResponseWriter: w, statusCode: 200}
		next.ServeHTTP(lw, r)
		log.Printf("[web] %s %s %d %s", r.Method, r.URL.Path, lw.statusCode, time.Since(start))
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lw *loggingResponseWriter) WriteHeader(code int) {
	lw.statusCode = code
	lw.ResponseWriter.WriteHeader(code)
}
