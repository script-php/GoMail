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
