package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// fakeCollector returns a single canned sample on every Collect() so the
// controller's Emit path has something to send. Doesn't model anything
// realistic; the test only cares about start/stop semantics.
type fakeCollector struct {
	collected atomic.Int32
}

func (c *fakeCollector) Collect() ([]transport.HostSample, error) {
	c.collected.Add(1)
	return []transport.HostSample{{Name: "test_metric", Value: 1, Timestamp: time.Now().UnixMilli()}}, nil
}

// fakeSender records Emit calls in order so the test can assert "no
// emits while gated off" without timing assumptions about the ticker.
type fakeSender struct {
	mu      sync.Mutex
	batches int
}

func (s *fakeSender) Emit(_ context.Context, _ []transport.HostSample) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches++
	return nil
}

func (s *fakeSender) batchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.batches
}

// TestHostMetricsController_GateOffByDefault_NoEmits proves that
// applying a nil gate (the "plan does not support metrics" tri-state)
// does NOT spawn a ticker. Before the controller refactor this was
// the static behaviour of RunHostMetrics; we want to preserve it.
func TestHostMetricsController_GateOffByDefault_NoEmits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	collector := &fakeCollector{}
	sender := &fakeSender{}
	ctrl := newHostMetricsController()
	ctrl.setRootCtx(ctx)
	ctrl.attach(collector, sender)

	ctrl.ApplyGate(nil) // plan does not support metrics

	// Give an eager ticker plenty of time to misfire.
	time.Sleep(120 * time.Millisecond)

	if got := sender.batchCount(); got != 0 {
		t.Errorf("emits while gate=off: got %d batches, want 0", got)
	}
	if got := collector.collected.Load(); got != 0 {
		t.Errorf("collected while gate=off: got %d, want 0", got)
	}
}

// TestHostMetricsController_GateFlipsOn_StartsCollector pins the
// trial-start path: the agent boots with the gate off (Free plan),
// the user starts a Pro trial, the next heartbeat carries
// {Enabled:true}, and the controller starts emitting within one tick.
func TestHostMetricsController_GateFlipsOn_StartsCollector(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	collector := &fakeCollector{}
	sender := &fakeSender{}
	ctrl := newHostMetricsController()
	ctrl.setRootCtx(ctx)
	ctrl.attach(collector, sender)

	ctrl.ApplyGate(nil) // gate off at startup
	ctrl.ApplyGate(&transport.HostMetricsConfig{Enabled: true, IntervalSeconds: 1})

	// First emit runs synchronously on start; assert that immediately.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && sender.batchCount() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := sender.batchCount(); got < 1 {
		t.Errorf("collector did not start: got %d batches after gate flip, want >=1", got)
	}
}

// TestHostMetricsController_GateFlipsOff_StopsCollector pins the
// trial-expiry path: collector is running, the cron clears the trial,
// the next heartbeat carries {Enabled:false}, the ticker stops.
func TestHostMetricsController_GateFlipsOff_StopsCollector(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	collector := &fakeCollector{}
	sender := &fakeSender{}
	ctrl := newHostMetricsController()
	ctrl.setRootCtx(ctx)
	ctrl.attach(collector, sender)

	ctrl.ApplyGate(&transport.HostMetricsConfig{Enabled: true, IntervalSeconds: 1})
	// Let the first synchronous emit land.
	time.Sleep(50 * time.Millisecond)
	startBatches := sender.batchCount()
	if startBatches < 1 {
		t.Fatalf("collector did not start: %d batches", startBatches)
	}

	ctrl.ApplyGate(&transport.HostMetricsConfig{Enabled: false}) // team paused

	// After flip-off, no further batches should land. Sleep > tick interval
	// to give a misbehaving controller every chance to over-emit.
	time.Sleep(150 * time.Millisecond)
	if got := sender.batchCount(); got != startBatches {
		t.Errorf("batches after gate-off: got %d, want %d (no further emits)", got, startBatches)
	}
}

// TestHostMetricsController_IntervalChange_RestartsTicker pins the
// plan-upgrade cadence flip: agent was ticking at 60s on Free, user
// subscribes to Pro, the next heartbeat carries IntervalSeconds=30,
// the ticker restarts at the new cadence.
//
// Test version uses 1s -> 0 (the second gate's wantInterval recomputes
// to 30s default - we just want to assert the goroutine restarted, not
// the exact cadence). The simplest observable: ApplyGate is idempotent
// on identical state, so an interval-change must restart the ticker
// (which we verify by observing a fresh immediate-emit).
func TestHostMetricsController_IntervalChange_RestartsTicker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	collector := &fakeCollector{}
	sender := &fakeSender{}
	ctrl := newHostMetricsController()
	ctrl.setRootCtx(ctx)
	ctrl.attach(collector, sender)

	ctrl.ApplyGate(&transport.HostMetricsConfig{Enabled: true, IntervalSeconds: 1})
	time.Sleep(50 * time.Millisecond)
	startBatches := sender.batchCount()

	// Change interval; controller must stop the old goroutine and start a
	// new one. The new one's immediate emit bumps the batch count.
	ctrl.ApplyGate(&transport.HostMetricsConfig{Enabled: true, IntervalSeconds: 2})
	time.Sleep(50 * time.Millisecond)
	afterChange := sender.batchCount()
	if afterChange <= startBatches {
		t.Errorf("interval change did not restart ticker: batches %d -> %d (want strictly more)", startBatches, afterChange)
	}
}

// TestHostMetricsController_GateFlipsOff_PlanUnsupported_StopsCollector
// pins the heartbeat-driven "plan downgraded / trial expired" path. The
// Console signals this by sending {Enabled:false, IntervalSeconds:0} on
// the heartbeat response (see handler_lighthouse_agent.go). The
// controller must stop the ticker. Distinct from the team-paused case
// above only at the log layer.
//
// This is the regression that originally shipped: the controller's
// only off-trigger was a nil cfg, but the heartbeat-loop guard
// (lifecycle.go) skips ApplyGate when the field is nil. Without an
// explicit "off" signal on the wire, the on-to-off flip never fired.
func TestHostMetricsController_GateFlipsOff_PlanUnsupported_StopsCollector(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	collector := &fakeCollector{}
	sender := &fakeSender{}
	ctrl := newHostMetricsController()
	ctrl.setRootCtx(ctx)
	ctrl.attach(collector, sender)

	ctrl.ApplyGate(&transport.HostMetricsConfig{Enabled: true, IntervalSeconds: 1})
	time.Sleep(50 * time.Millisecond)
	startBatches := sender.batchCount()
	if startBatches < 1 {
		t.Fatalf("collector did not start: %d batches", startBatches)
	}

	// Plan-unsupported sentinel on the wire. Equivalent to team-paused
	// at the controller level but distinguished in the log line.
	ctrl.ApplyGate(&transport.HostMetricsConfig{Enabled: false, IntervalSeconds: 0})

	time.Sleep(150 * time.Millisecond)
	if got := sender.batchCount(); got != startBatches {
		t.Errorf("batches after plan-unsupported gate: got %d, want %d", got, startBatches)
	}
}

// TestHostMetricsController_ApplyGate_BeforeRunHostMetrics_NoPanic
// proves the controller is panic-safe when ApplyGate fires before
// RunHostMetrics has supplied a shutdown-aware rootCtx. NewRunner
// constructs the controller with rootCtx=Background so a heartbeat
// landing during startup can't race the host-metrics goroutine.
func TestHostMetricsController_ApplyGate_BeforeRunHostMetrics_NoPanic(t *testing.T) {
	// Fresh controller, no setRootCtx, no attach.
	ctrl := newHostMetricsController()

	// Without the Background default, this would panic on
	// context.WithCancel(nil). Recover so the test reports a
	// readable failure if the default regresses.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ApplyGate panicked with no rootCtx: %v", r)
		}
	}()

	// nil gate is a no-op (interval stays 0), but the path through
	// ApplyGate must still complete safely.
	ctrl.ApplyGate(nil)
	// {Enabled:false} hits the same wantInterval=0 path.
	ctrl.ApplyGate(&transport.HostMetricsConfig{Enabled: false, IntervalSeconds: 0})

	// An {Enabled:true} gate WOULD spawn an inner goroutine via
	// context.WithCancel(rootCtx) - that's the panic-prone path. With
	// rootCtx=Background it just spawns a goroutine running against
	// Background; shutdown() reaps it.
	collector := &fakeCollector{}
	sender := &fakeSender{}
	ctrl.attach(collector, sender)
	ctrl.ApplyGate(&transport.HostMetricsConfig{Enabled: true, IntervalSeconds: 1})
	time.Sleep(20 * time.Millisecond)
	ctrl.shutdown()
}

// TestHostMetricsController_Shutdown_StopsAcceptingGates proves the
// graceful-shutdown path: once shutdown() returns, a subsequent
// ApplyGate must NOT spawn a new ticker.
func TestHostMetricsController_Shutdown_StopsAcceptingGates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	collector := &fakeCollector{}
	sender := &fakeSender{}
	ctrl := newHostMetricsController()
	ctrl.setRootCtx(ctx)
	ctrl.attach(collector, sender)

	ctrl.ApplyGate(&transport.HostMetricsConfig{Enabled: true, IntervalSeconds: 1})
	time.Sleep(50 * time.Millisecond)
	ctrl.shutdown()
	preShutdownBatches := sender.batchCount()

	// Apply a fresh gate post-shutdown; it should be a no-op.
	ctrl.ApplyGate(&transport.HostMetricsConfig{Enabled: true, IntervalSeconds: 1})
	time.Sleep(50 * time.Millisecond)

	if got := sender.batchCount(); got != preShutdownBatches {
		t.Errorf("ApplyGate after shutdown spawned new ticker: %d -> %d (want unchanged)", preShutdownBatches, got)
	}
}
