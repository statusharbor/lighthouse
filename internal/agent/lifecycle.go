package agent

import (
	"context"
	"errors"
	"log/slog"
	"math/rand"
	"reflect"
	"sync"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// supervisorTickInterval governs how often RunScheduler reconciles its
// per-check goroutines against the runner's current Checks(). Exported as
// a var (not const) so tests can shrink it without waiting 30s per
// reconcile cycle.
var supervisorTickInterval = 30 * time.Second

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
			_, err := r.SendHeartbeat(ctx)
			if err != nil {
				if errors.Is(err, transport.ErrLighthouseGone) {
					return err
				}
				slog.Warn("heartbeat failed; will retry on next tick",
					"interval", interval, "error", err)
				continue
			}
			if r.health != nil {
				r.health.RecordHeartbeat()
			}
		}
	}
}

// scheduledCheck is the supervisor's bookkeeping per running check.
// Storing the def alongside the cancel lets the supervisor detect when a
// check's configuration has changed (interval, URL, headers, etc.) and
// restart the goroutine — without this, the per-check goroutine captures
// the def by value at spawn time and ignores subsequent ApplyConfig
// updates forever.
type scheduledCheck struct {
	cancel context.CancelFunc
	def    CheckDefinition
}

// RunScheduler is the per-check scheduler loop. Each check gets its own
// goroutine ticking at its interval_seconds, jittered within the first
// minute to avoid thundering-herd at :00. Observations are submitted to
// the worker pool so concurrency is capped at max_concurrent_checks.
//
// Skips check execution while the lighthouse is paused (heartbeats
// continue regardless). On every supervisorTickInterval the supervisor
// reconciles the goroutine set against the runner's current Checks():
//   - removed checks → goroutine cancelled
//   - added checks → goroutine spawned
//   - mutated checks (any field change) → goroutine restarted with the
//     fresh def (otherwise the captured-by-value def stays stale)
//
// Returns when ctx ends; on shutdown the caller should already have
// stopped accepting new work via context cancellation.
func (r *Runner) RunScheduler(ctx context.Context) error {
	pool := newWorkerPool(r.cfg.Agent.MaxConcurrentChecks)

	var wg sync.WaitGroup
	scheduled := map[string]scheduledCheck{}
	supervisorTick := time.NewTicker(supervisorTickInterval)
	defer supervisorTick.Stop()

	spawn := func(def CheckDefinition) {
		subCtx, cancel := context.WithCancel(ctx)
		scheduled[def.ID] = scheduledCheck{cancel: cancel, def: def}
		wg.Add(1)
		go func(d CheckDefinition) {
			defer wg.Done()
			r.runCheckLoop(subCtx, d, pool)
		}(def)
	}

	refresh := func() {
		want := map[string]CheckDefinition{}
		for _, def := range r.Checks() {
			want[def.ID] = def
		}
		// Pass 1: cancel goroutines for checks that disappeared OR whose
		// def changed. Restarted ones get respawned in pass 2.
		for id, sc := range scheduled {
			newDef, stillWanted := want[id]
			if !stillWanted {
				sc.cancel()
				delete(scheduled, id)
				continue
			}
			if !reflect.DeepEqual(sc.def, newDef) {
				slog.Info("check definition changed; restarting goroutine",
					"check_id", id,
					"old_interval_s", sc.def.IntervalSeconds,
					"new_interval_s", newDef.IntervalSeconds)
				sc.cancel()
				delete(scheduled, id)
			}
		}
		// Pass 2: spawn goroutines for new (or just-restarted) checks.
		for id, def := range want {
			if _, ok := scheduled[id]; ok {
				continue
			}
			spawn(def)
			_ = id
		}
	}
	refresh()

	for {
		select {
		case <-ctx.Done():
			for _, sc := range scheduled {
				sc.cancel()
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
	var jitter time.Duration
	if maxJitter > 0 {
		jitter = time.Duration(rand.Int63n(int64(maxJitter)))
	}
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
