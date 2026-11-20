package dns

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stalledPTRResolver struct{ forward bool }

func (r stalledPTRResolver) LookupAddr(ctx context.Context, _ string) ([]string, error) {
	if !r.forward {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return []string{"mx.example.test."}, nil
}

func (r stalledPTRResolver) LookupHost(ctx context.Context, _ string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestPTRLookupSharesDeadlineAcrossReverseAndForward(t *testing.T) {
	InitCache(60)
	for _, forward := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		start := time.Now()
		_, valid, err := verifyPTR(ctx, stalledPTRResolver{forward: forward}, "192.0.2.231")
		cancel()
		if valid || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("forward=%v valid=%v err=%v", forward, valid, err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("PTR lookup ignored deadline: %s", elapsed)
		}
	}
}
