package agent

import (
	"context"
	"log/slog"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// RunHostMetrics is the host-metrics ticker. Mirrors the shape of
// RunHeartbeat / RunScheduler so cmd/lighthouse/main.go spawns it in the same
// long-running-goroutines block. Returns when ctx is done; never retries on
// individual emit failures (the Sender returns the error; we log + continue).
//
// Gating: the caller passes the HostMetricsConfig from /register.
//   - nil               → never collect (plan does not support metrics)
//   - {Enabled: false}  → never collect (team paused)
//   - {Enabled: true,…} → tick every IntervalSeconds and Emit
//
// The /register response is checked once at startup; the agent doesn't
// re-read it on heartbeat. Toggling the team's plan off therefore needs the
// agent to restart (or, future: a heartbeat-side signal). This matches the
// design's §3.1 "(restart to apply)" wording.
//
// Errors from a single Emit are logged but do not stop the ticker — the next
// tick gets a fresh batch. This is intentionally NOT wired to the existing
// disk buffer: host-metric series are fungible (a missed tick is a missed
// data point, not a missed event); buffering+replay would cost disk for
// little gain. Compare to /events where a missed transition is lost forever.
func (r *Runner) RunHostMetrics(ctx context.Context, cfg *transport.HostMetricsConfig, collector Collector, sender transport.HostMetricsSender) {
	if cfg == nil {
		slog.Info("host-metrics collector disabled (plan does not support metrics)")
		return
	}
	if !cfg.Enabled {
		slog.Info("host-metrics collector disabled (team paused)")
		return
	}
	interval := time.Duration(cfg.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}
	slog.Info("host-metrics collector started", "interval", interval)

	// First tick happens immediately on start so the dashboard has data
	// within the interval rather than after it. On Linux the FIRST CPU tick
	// emits no CPU samples (the delta needs a prior snapshot) — that's
	// expected; the second tick onwards is real. Memory/load/disk are
	// snapshots and emit on every tick including the first.
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
