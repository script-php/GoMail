package smtp

import (
	"fmt"
	"testing"
	"time"
)

func TestRateLimiterBoundsDistinctClients(t *testing.T) {
	rl := NewRateLimiter(2, 2)
	for i := 0; i < maxRateWindowClients; i++ {
		if !rl.AllowConnection(fmt.Sprintf("192.0.2.%d", i)) {
			t.Fatalf("premature cap at %d", i)
		}
	}
	if rl.AllowConnection("extra") || len(rl.connections) != maxRateWindowClients {
		t.Fatal("new IP bypassed full limiter")
	}
	if !rl.AllowConnection("192.0.2.0") {
		t.Fatal("known IP was denied before its limit")
	}
	rl.connections["192.0.2.0"].timestamps = []time.Time{time.Now().Add(-2 * time.Minute)}
	if !rl.AllowConnection("extra") || len(rl.connections) > maxRateWindowClients {
		t.Fatal("expired entry was not reclaimed")
	}
}
