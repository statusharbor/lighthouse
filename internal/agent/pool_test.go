package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkerPool_CapsConcurrency(t *testing.T) {
	const cap = 3
	pool := newWorkerPool(cap)

	var inFlight, peak atomic.Int32
	var wg sync.WaitGroup
	wg.Add(10)
	for range 10 {
		go func() {
			defer wg.Done()
			_ = pool.Submit(context.Background(), func() {
				cur := inFlight.Add(1)
				for {
					p := peak.Load()
					if cur <= p || peak.CompareAndSwap(p, cur) {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
				inFlight.Add(-1)
			})
		}()
	}
	wg.Wait()

	if peak.Load() > cap {
		t.Errorf("peak in-flight = %d, want ≤ %d", peak.Load(), cap)
	}
}

func TestWorkerPool_RespectsContextCancellation(t *testing.T) {
	pool := newWorkerPool(1)

	// Hold the slot.
	hold := make(chan struct{})
	released := make(chan struct{})
	go func() {
		_ = pool.Submit(context.Background(), func() {
			<-hold
			close(released)
		})
	}()
	// Give the goroutine time to acquire.
	time.Sleep(10 * time.Millisecond)

	// New submission with already-cancelled ctx should return immediately
	// rather than block on the slot.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := pool.Submit(ctx, func() { t.Error("fn must not run on cancelled ctx") })
	if err == nil {
		t.Error("expected ctx.Err()")
	}

	close(hold)
	<-released
}
