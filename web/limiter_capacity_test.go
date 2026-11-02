package web

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestWebRateLimiterBoundsDistinctClients(t *testing.T) {
	rl := NewWebRateLimiter(2)
	for i := 0; i < maxWebRateClients; i++ {
		rl.clients[strconv.Itoa(i)] = &webRateEntry{count: 1, resetAt: time.Now().Add(time.Minute)}
	}
	hit := 0
	handler := rl.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit++ }))
	request := httptest.NewRequest(http.MethodGet, "/inbox", nil)
	request.RemoteAddr = "203.0.113.1:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || hit != 0 || len(rl.clients) != maxWebRateClients {
		t.Fatalf("full limiter status=%d hits=%d entries=%d", response.Code, hit, len(rl.clients))
	}
	for _, entry := range rl.clients {
		entry.resetAt = time.Now().Add(-time.Second)
		break
	}
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if hit != 1 || len(rl.clients) > maxWebRateClients {
		t.Fatal("expired web entry was not reclaimed")
	}
}

func TestLoginRateLimiterBoundsDistinctClients(t *testing.T) {
	lr := NewLoginRateLimiter()
	for i := 0; i < maxLoginRateClients; i++ {
		lr.attempts[strconv.Itoa(i)] = &loginAttempt{lastAttempt: time.Now()}
	}
	if blocked, _ := lr.IsBlocked("new-ip"); !blocked {
		t.Fatal("unknown IP bypassed full login limiter")
	}
	if len(lr.attempts) > maxLoginRateClients {
		t.Fatal("login limiter exceeded cap")
	}
	for _, entry := range lr.attempts {
		entry.lastAttempt = time.Now().Add(-time.Hour)
		break
	}
	lr.RecordFailure("new-ip")
	if blocked, _ := lr.IsBlocked("new-ip"); blocked {
		t.Fatal("reclaimed login slot stayed blocked")
	}
}
