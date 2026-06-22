package agent

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// RunHostMetrics is the host-metrics ticker. Mirrors the shape of
// RunHeartbeat / RunScheduler so cmd/lighthouse/main.go spawns it in the same
// long-running-goroutines block. Returns when ctx is done; never retries on
// individual emit failures (the Sender returns the error; we log + continue).
//
// Lifecycle is driven by HostMetricsController.ApplyGate so the heartbeat
// loop can flip the collector on / off / change interval without a process
// restart. Initial gate comes from the /register response and is applied
// here before the supervisor loop starts.
//
// Gating tri-state (mirrors transport.HostMetricsConfig):
//   - nil               → never collect (plan does not support metrics)
//   - {Enabled: false}  → never collect (team paused OR plan unsupported)
//   - {Enabled: true,…} → tick every IntervalSeconds and Emit
//
// Errors from a single Emit are logged but do not stop the ticker - the next
// tick gets a fresh batch. This is intentionally NOT wired to the existing
// disk buffer: host-metric series are fungible (a missed tick is a missed
// data point, not a missed event); buffering+replay would cost disk for
// little gain. Compare to /events where a missed transition is lost forever.
func (r *Runner) RunHostMetrics(ctx context.Context, cfg *transport.HostMetricsConfig, collector Collector, sender transport.HostMetricsSender) {
	ctrl := r.HostMetricsController()
	ctrl.setRootCtx(ctx)
	ctrl.attach(collector, sender)
	ctrl.ApplyGate(cfg)
	// Block until shutdown; ApplyGate spawns / cancels the inner ticker
	// goroutine in response to heartbeat updates from RunHeartbeat.
	<-ctx.Done()
	ctrl.shutdown()
}

// HostMetricsController owns the collector goroutine lifecycle. Heartbeat
// responses funnel through ApplyGate; the controller decides whether to
// start, restart (interval change), or stop the inner ticker.
//
// Concurrency: ApplyGate can fire from the heartbeat loop while the inner
// ticker goroutine is mid-emit. mu serialises ApplyGate calls + protects
// the runState fields; the inner goroutine doesn't take mu while emitting
// so a slow Emit (15s timeout) can't block a fast gate flip.
type HostMetricsController struct {
	mu        sync.Mutex
	collector Collector
	sender    transport.HostMetricsSender
	rootCtx   context.Context

	// Current effective state. interval==0 means "not running"; non-zero
	// means a ticker goroutine is alive with that interval.
	interval time.Duration
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	// closed once shutdown() runs so ApplyGate stops accepting new starts
	// during teardown.
	stopped bool
}

// newHostMetricsController constructs a controller with rootCtx defaulted
// to Background so ApplyGate is panic-safe even before RunHostMetrics has
// supplied the shutdown-aware ctx. Eager construction in NewRunner means
// heartbeat-driven ApplyGate calls never race the host-metrics goroutine.
func newHostMetricsController() *HostMetricsController {
	return &HostMetricsController{rootCtx: context.Background()}
}

// HostMetricsController returns the controller attached to this Runner.
// Constructed eagerly in NewRunner; callers can rely on the pointer
// being non-nil across the Runner's lifetime.
func (r *Runner) HostMetricsController() *HostMetricsController {
	return r.hmCtrl
}

// attach wires the static dependencies (collector, sender). Called once
// from RunHostMetrics before the first ApplyGate. Separated from
// construction because the collector / sender are built lazily in main.go
// after the role-conditional logic.
func (c *HostMetricsController) attach(collector Collector, sender transport.HostMetricsSender) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.collector = collector
	c.sender = sender
}

// ApplyGate is the heartbeat-callable signal: tri-state cfg drives
// start / stop / interval-change.
//
//   - cfg == nil           → "plan does not support metrics" (the /register
//     contract; on /heartbeat the agent's lifecycle guard converts the
//     absent-field case to "no change" - so nil only reaches here from
//     /register or from explicit start-up code).
//   - cfg != nil, !Enabled → gate is off (team paused OR plan flipped to
//     unsupported via a plan downgrade / trial expiry). Stops the ticker.
//   - cfg != nil, Enabled  → start (or restart on interval change).
//
// Idempotent: applying the same gate twice is a no-op. Interval changes
// (e.g. user upgraded from Free=60s to Pro=30s) restart the ticker so
// the new cadence takes effect immediately.
func (c *HostMetricsController) ApplyGate(cfg *transport.HostMetricsConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return
	}

	wantInterval := time.Duration(0)
	if cfg != nil && cfg.Enabled {
		wantInterval = time.Duration(cfg.IntervalSeconds) * time.Second
		if wantInterval <= 0 {
			wantInterval = 30 * time.Second
		}
	}

	if wantInterval == c.interval {
		return // already in the desired state
	}

	// Either off→on, on→off, or on with a different interval. Stop the
	// current goroutine (if any) before starting a new one - prevents
	// two concurrent tickers during an interval change.
	if c.cancel != nil {
		c.cancel()
		c.wg.Wait()
		c.cancel = nil
	}
	c.interval = wantInterval

	if wantInterval == 0 {
		// Two "off" reasons:
		//   - cfg == nil OR cfg.IntervalSeconds == 0 → plan doesn't
		//     support metrics. nil case is /register from an older
		//     Console; IntervalSeconds=0 is the heartbeat-side
		//     sentinel the Console sends when MetricsEnabled flipped
		//     to false (downgrade, trial expiry, admin demotion).
		//   - cfg != nil && cfg.IntervalSeconds > 0 && !Enabled →
		//     team paused (plan still supports metrics, lighthouse
		//     happens to be paused right now).
		planUnsupported := cfg == nil || cfg.IntervalSeconds == 0
		if planUnsupported {
			slog.Info("host-metrics collector disabled (plan does not support metrics)")
		} else {
			slog.Info("host-metrics collector disabled (team paused)")
		}
		return
	}

	subCtx, cancel := context.WithCancel(c.rootCtx)
	c.cancel = cancel
	collector := c.collector
	sender := c.sender
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.runTicker(subCtx, wantInterval, collector, sender)
	}()
	slog.Info("host-metrics collector started", "interval", wantInterval)
}

// runTicker is the inner emit loop. Lifted out of ApplyGate so the
// nil-cfg / enabled-false branches don't have to defer t.Stop on a
// nil ticker. First emit runs immediately so a freshly-enabled gate
// produces data before one full interval has elapsed.
func (c *HostMetricsController) runTicker(ctx context.Context, interval time.Duration, collector Collector, sender transport.HostMetricsSender) {
	// Inject the cancellable ctx into collectors that opt in. Plain
	// collectors (noop, /proc reader) silently ignore.
	applyContext(collector, ctx)

	emit := func() {
		samples, err := collector.Collect()
		if err != nil {
			slog.Warn("host-metrics collect failed", "error", err)
			return
		}
		if len(samples) == 0 {
			return
		}
		emitCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := sender.Emit(emitCtx, samples); err != nil {
			slog.Warn("host-metrics emit failed", "error", err, "samples", len(samples))
			return
		}
		slog.Debug("host-metrics emitted", "samples", len(samples))
	}

	emit()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("host-metrics collector stopping")
			return
		case <-t.C:
			emit()
		}
	}
}

// shutdown cancels any running ticker and blocks new ApplyGate calls.
// Called by RunHostMetrics on root-ctx done.
func (c *HostMetricsController) shutdown() {
	c.mu.Lock()
	c.stopped = true
	cancel := c.cancel
	c.cancel = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
		c.wg.Wait()
	}
}

// setRootCtx is called from RunHostMetrics so ApplyGate can spawn
// child contexts off the right parent. Kept private because the
// controller's lifecycle is owned by Runner + RunHostMetrics.
func (c *HostMetricsController) setRootCtx(ctx context.Context) {
	c.mu.Lock()
	c.rootCtx = ctx
	c.mu.Unlock()
}
