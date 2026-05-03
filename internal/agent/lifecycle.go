package agent

import (
	"context"
	"errors"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// RunHeartbeat ticks SendHeartbeat at the given interval until ctx ends or
// the Console returns 410 Gone. Returns ErrLighthouseGone in that case so
// main can exit(0). Per design §4.2 there is no retry — a failed heartbeat
// is dropped and the next tick is the retry.
func (r *Runner) RunHeartbeat(ctx context.Context, interval time.Duration) error {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if _, err := r.SendHeartbeat(ctx); err != nil {
				if errors.Is(err, transport.ErrLighthouseGone) {
					return err
				}
				slog.Warn("heartbeat failed; will retry on next tick",
					"interval", interval, "error", err)
			}
		}
	}
}

// RunScheduler is the per-check scheduler loop. Each check gets its own
// goroutine ticking at its interval_seconds, jittered within the first
// minute to avoid thundering-herd at :00. Observations are submitted to
// the worker pool so concurrency is capped at max_concurrent_checks.
//
// Skips check execution while the lighthouse is paused (heartbeats
// continue regardless). Re-reads the check list every iteration so
// config refresh from heartbeat takes effect on the next interval tick.
//
// Returns when ctx ends; on shutdown the caller should already have
// stopped accepting new work via context cancellation.
func (r *Runner) RunScheduler(ctx context.Context) error {
	pool := newWorkerPool(r.cfg.Agent.MaxConcurrentChecks)

	// One goroutine per check. We restart this loop when the check set
	// changes (etag rotation in heartbeat) — but the simplest correct
	// implementation polls Checks() each iteration of the per-check
	// timer. New checks get picked up on the next supervisor refresh
	// (every 30s).
	var wg sync.WaitGroup
	scheduled := map[string]context.CancelFunc{}
	supervisorTick := time.NewTicker(30 * time.Second)
	defer supervisorTick.Stop()

	refresh := func() {
		want := map[string]CheckDefinition{}
		for _, def := range r.Checks() {
			want[def.ID] = def
		}
		// Cancel goroutines for checks that no longer exist.
		for id, cancel := range scheduled {
			if _, ok := want[id]; !ok {
				cancel()
				delete(scheduled, id)
			}
		}
		// Spawn goroutines for new checks.
		for id, def := range want {
			if _, ok := scheduled[id]; ok {
				continue
			}
			subCtx, cancel := context.WithCancel(ctx)
			scheduled[id] = cancel
			wg.Add(1)
			go func(d CheckDefinition) {
				defer wg.Done()
				r.runCheckLoop(subCtx, d, pool)
			}(def)
		}
	}
	refresh()

	for {
		select {
		case <-ctx.Done():
			for _, cancel := range scheduled {
				cancel()
			}
			wg.Wait()
			return nil
		case <-supervisorTick.C:
			refresh()
		}
	}
}

// runCheckLoop is one goroutine per check. Sleeps a small random jitter
// up front to spread tick boundaries across checks, then ticks at the
// check's interval. Skips while paused.
func (r *Runner) runCheckLoop(ctx context.Context, def CheckDefinition, pool *workerPool) {
	interval := time.Duration(def.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}
	// Jitter the first tick to avoid stampedes when many checks share an
	// interval. Bounded by interval/4 so we don't delay observably.
	maxJitter := interval / 4
	if maxJitter < time.Second {
		maxJitter = time.Second
	}
	jitter := time.Duration(rand.Int63n(int64(maxJitter)))
	select {
	case <-ctx.Done():
		return
	case <-time.After(jitter):
	}

	t := time.NewTicker(interval)
	defer t.Stop()
	tick := func() {
		if r.IsPaused() {
			return
		}
		_ = pool.Submit(ctx, func() {
			if err := r.ObserveAndEmit(ctx, def); err != nil {
				slog.Warn("observe and emit failed",
					"check_id", def.ID, "error", err)
			}
		})
	}
	tick() // run once immediately so we don't wait a full interval
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}
