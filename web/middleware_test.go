package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrustedProxyMiddleware(t *testing.T) {
	var got string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = extractIP(r) })
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
			TrustedProxyMiddleware([]string{"10.0.0.0/8"}, next).ServeHTTP(httptest.NewRecorder(), r)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
