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

// supervisorTickInterval governs how often RunScheduler reconciles its
// per-check goroutines against the runner's current Checks(). Exported as
// a var (not const) so tests can shrink it without waiting 30s per
// reconcile cycle.
var supervisorTickInterval = 30 * time.Second

// minCheckIntervalFloor clamps the per-check tick interval to a sane
// minimum on the agent side. The Console enforces a 5s floor on
// create/update of lighthouse-bound monitors, so in normal operation
// the agent never sees a smaller value — but a misconfigured DB row
// or a future server bug shouldn't be able to make the agent pound
// the target every fraction of a second. var (not const) so tests
// can override.
var minCheckIntervalFloor = 5 * time.Second

// heartbeatMaxBackoff caps the failure backoff. The Console's offline
// watchdog tolerates a 60s gap before marking an agent offline, so backing
// off past that would flap the agent's liveness for no gain. A server
// Retry-After larger than this is still honoured verbatim - that's an
// explicit "come back later" from the Console, not our own guess.
const heartbeatMaxBackoff = 60 * time.Second

// jitterInterval perturbs d by +-20% so a fleet of agents that all
// reconnected at the same instant (e.g. after a Console redeploy) re-spread
// their heartbeats across the interval instead of stampeding the Console on
// the same tick. Non-positive d is returned unchanged.
func jitterInterval(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	// Multiplier in [0.8, 1.2).
	j := time.Duration(float64(d) * (0.8 + rand.Float64()*0.4))
	if j <= 0 {
		j = d
	}
	return j
}

// nextHeartbeatBackoff computes the delay before the next beat after a
// failure. A server Retry-After on a 429 / 5xx wins (honoured verbatim);
// otherwise the previous backoff doubles, seeded from the base interval,
// capped at heartbeatMaxBackoff.
func nextHeartbeatBackoff(prev, base time.Duration, err error) time.Duration {
	var re *transport.RetryableStatusError
	if errors.As(err, &re) && re.RetryAfter > 0 {
		return re.RetryAfter
	}
	next := prev * 2
	if next <= 0 {
		next = base
	}
	if next > heartbeatMaxBackoff {
		next = heartbeatMaxBackoff
	}
	return next
}

// RunHeartbeat beats SendHeartbeat until ctx ends or the Console returns 410
// Gone. Returns ErrLighthouseGone in that case so main can exit(0). Per
// design §4.2 there is no in-beat retry - a failed beat is dropped and the
// next scheduled beat is the retry.
//
// Cadence: each healthy beat is scheduled at interval +-20% jitter. On a
// 429 / 5xx the loop backs off (honouring a server Retry-After, else
// exponential capped at 60s) and resets to the jittered base cadence on the
// next success.
func (r *Runner) RunHeartbeat(ctx context.Context, interval time.Duration) error {
	// backoff tracks the current failure penalty; 0 means "healthy, use the
	// jittered base cadence".
	var backoff time.Duration
	timer := time.NewTimer(jitterInterval(interval))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			resp, err := r.SendHeartbeat(ctx)
			if err != nil {
				if errors.Is(err, transport.ErrLighthouseGone) {
					return err
				}
				backoff = nextHeartbeatBackoff(backoff, interval, err)
				slog.Warn("heartbeat failed; backing off before next beat",
					"backoff", backoff, "error", err)
				timer.Reset(backoff)
				continue
			}
			// Success - clear any backoff and return to the jittered cadence.
			backoff = 0
			timer.Reset(jitterInterval(interval))
			if r.health != nil {
				r.health.RecordHeartbeat()
			}
			// Plumb the host-metrics gate refresh through the
			// controller. ApplyGate is idempotent on a no-change
			// response, so the steady-state cost is one map lookup
			// + interval comparison. The tri-state contract on the
			// wire (nil = "no signal from server", non-nil = "this
			// is the new gate") is preserved end-to-end.
			if resp != nil && resp.HostMetrics != nil {
				r.HostMetricsController().ApplyGate(resp.HostMetrics)
			}
			// Databases gate - enabled flips apply live; the cluster+DSN
			// payload is fetched from /config only when the DATABASES-section
			// etag moved (#11), so a monitor edit that bumps only the checks
			// section doesn't re-pull the DSN gate.
			if resp != nil {
				r.ApplyDatabaseGate(ctx, resp.Databases, databasesEtag(resp))
			}
		}
	}
}

// databasesEtag returns the etag that gates a database-gate refetch (#11).
// It prefers the per-section value config_etags["databases"] so a change
// confined to another section (e.g. a monitor edit bumping "checks") leaves
// it stable and skips the DSN-gate refetch. When the Console sends no
// config_etags map (older build), it falls back to the scalar config_etag,
// preserving the previous refetch-on-any-change behaviour.
func databasesEtag(resp *transport.HeartbeatResponse) string {
	if len(resp.ConfigEtags) > 0 {
		// Present but missing the databases key means the section is not
		// configured; "" is stable, so no refetch is triggered.
		return resp.ConfigEtags[transport.DatabasesConfigSection]
	}
	return resp.ConfigEtag
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
			if !sc.def.Equal(newDef) {
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

// resolveCheckInterval turns a CheckDefinition's IntervalSeconds into
// the actual ticker interval, applying:
//   - a 60s fallback when the value is missing/zero, and
//   - a floor (minCheckIntervalFloor) so a misconfigured server can't
//     make the agent hammer the target.
//
// Logs a warning when clamping fires so anyone debugging unexpectedly
// slow checks can see the cause.
func resolveCheckInterval(checkID string, intervalSeconds int) time.Duration {
	interval := time.Duration(intervalSeconds) * time.Second
	if interval <= 0 {
		return 60 * time.Second
	}
	if interval < minCheckIntervalFloor {
		slog.Warn("check interval below floor; clamping",
			"check_id", checkID,
			"requested_s", intervalSeconds,
			"floor_s", int(minCheckIntervalFloor.Seconds()))
		return minCheckIntervalFloor
	}
	return interval
}

// runCheckLoop is one goroutine per check. Sleeps a small random jitter
// up front to spread tick boundaries across checks, then ticks at the
// check's interval. Skips while paused.
func (r *Runner) runCheckLoop(ctx context.Context, def CheckDefinition, pool *workerPool) {
	interval := resolveCheckInterval(def.ID, def.IntervalSeconds)
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
