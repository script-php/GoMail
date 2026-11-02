package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gomail/config"
)

func TestTrustedProxyMiddleware(t *testing.T) {
	var got string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = extractIP(r)
		if r.Header.Get("CF-Connecting-IP") != "" {
			t.Error("untrusted provider-specific client IP reached handlers")
		}
	})
	tests := []struct{ name, remote, xff, want string }{
		{"untrusted spoof", "203.0.113.9:1234", "1.2.3.4", "203.0.113.9"},
		{"trusted proxy", "10.0.0.2:1234", "198.51.100.4", "198.51.100.4"},
		{"trusted chain", "10.0.0.2:1234", "198.51.100.4, 10.0.0.3", "198.51.100.4"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.remote
			r.Header.Set("X-Forwarded-For", tc.xff)
			r.Header.Set("CF-Connecting-IP", "192.0.2.200")
			TrustedProxyMiddleware([]string{"10.0.0.0/8"}, next).ServeHTTP(httptest.NewRecorder(), r)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestRateLimiterIgnoresSpoofedForwardingHeaders(t *testing.T) {
	cfg := &config.Config{}
	cfg.Web.RateLimitPerMin = 2
	server := NewServer(cfg, nil, nil, nil)
	for i, spoofed := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.RemoteAddr = "203.0.113.9:1234"
		req.Header.Set("X-Forwarded-For", spoofed)
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, req)
		if i < 2 && response.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d was limited early", i)
		}
		if i == 2 && response.Code != http.StatusTooManyRequests {
			t.Fatalf("spoofed client IP bypassed limit: status %d", response.Code)
		}
	}
}
