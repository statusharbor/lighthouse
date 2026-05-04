package agent

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// Runner orchestrates the agent lifecycle: register, initial-sync,
// heartbeat ticker, edge-triggered transition emission. Graceful shutdown
// + buffer + flap protection arrive in subsequent slices.
type Runner struct {
	cfg      *Config
	client   *transport.Client
	executor CheckExecutor

	// State tracked across the run — committed state per check_id used for
	// transition detection. Protected by mu (scheduler & heartbeater write
	// concurrently from worker goroutines).
	mu        sync.Mutex
	state     map[string]State
	latencies map[string]transport.LatencyEntry
	etag      string
	buffer    *EventBuffer
	checks    []CheckDefinition
	flap      *flapTracker
	paused    bool
	health    *HealthState
}

// NewRunner wires a Runner. The executor abstraction is what tests stub.
func NewRunner(cfg *Config, client *transport.Client, executor CheckExecutor) *Runner {
	return &Runner{
		cfg:       cfg,
		client:    client,
		executor:  executor,
		state:     map[string]State{},
		latencies: map[string]transport.LatencyEntry{},
		flap:      newFlapTracker(1), // threshold updated by Register/Heartbeat config
	}
}

// ApplyConfig adopts a fresh checks list + flap-protection threshold from
// either /register or a /heartbeat that returned a new etag. Atomic swap
// under the runner mutex so the scheduler reads a consistent view.
//
// Returns the subset of `checks` whose IDs were not present in the previous
// list — callers running the heartbeat path use this to seed initial-sync
// for monitors that arrived post-startup (without a re-sync these checks
// would never emit a state event because the flap tracker treats them as
// committed-state-unknown forever; see flap.Observe).
func (r *Runner) ApplyConfig(checks []CheckDefinition, flapThreshold int, paused bool) []CheckDefinition {
	r.mu.Lock()
	defer r.mu.Unlock()
	prev := make(map[string]struct{}, len(r.checks))
	for _, c := range r.checks {
		prev[c.ID] = struct{}{}
	}
	var added []CheckDefinition
	for _, c := range checks {
		if _, ok := prev[c.ID]; !ok {
			added = append(added, c)
		}
	}
	r.checks = checks
	r.flap.SetThreshold(flapThreshold)
	r.paused = paused
	return added
}

// Checks returns a snapshot of the current check set. Scheduler reads this
// each tick.
func (r *Runner) Checks() []CheckDefinition {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]CheckDefinition, len(r.checks))
	copy(out, r.checks)
	return out
}

// IsPaused reports the latest server-side paused flag. The scheduler uses
// it to skip check execution while paused (heartbeats continue).
func (r *Runner) IsPaused() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.paused
}

// SetEtag records the latest config etag. The heartbeater includes it on
// every request; the server uses it to short-circuit when the agent's
// view of config matches the server's.
func (r *Runner) SetEtag(etag string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.etag = etag
}

// RunInitialSync performs one observation per check and POSTs them all as
// a single initial-sync batch (per design §7.3 step 3-4 + §3.2
// Interpretation B: prev_state=NULL on every row).
//
// Returns the committed state map so the scheduler can detect subsequent
// transitions against it. The map is also stored on the Runner.
func (r *Runner) RunInitialSync(ctx context.Context, defs []CheckDefinition) error {
	events := make([]transport.EventInput, 0, len(defs))
	for _, def := range defs {
		obs := r.executor.Run(ctx, def)
		r.commit(def.ID, obs.State)

		ev := transport.EventInput{
			CheckID:         def.ID,
			PrevState:       nil, // initial-sync sentinel
			NewState:        string(obs.State),
			AgentObservedAt: orNow(obs.ObservedAt),
		}
		if obs.ResponseTimeMs > 0 {
			ev.ResponseTimeMs = ptr(obs.ResponseTimeMs)
		}
		if obs.StatusCode > 0 {
			ev.StatusCode = ptr(obs.StatusCode)
		}
		if obs.ErrorMessage != "" {
			ev.ErrorMessage = ptr(obs.ErrorMessage)
		}
		events = append(events, ev)
	}

	if len(events) == 0 {
		return nil
	}
	_, err := r.client.SendEvents(ctx, transport.EventsRequest{
		IsInitialSync: true,
		Events:        events,
	})
	return err
}

// State returns a snapshot of the committed state map.
func (r *Runner) State() map[string]State {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]State, len(r.state))
	for k, v := range r.state {
		out[k] = v
	}
	return out
}

func (r *Runner) commit(checkID string, s State) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state[checkID] = s
}

// recordLatency stashes a per-check latency snapshot for the next heartbeat.
// Called by the scheduler after every observation.
func (r *Runner) recordLatency(checkID string, latencyMs int, observedAt time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.latencies[checkID] = transport.LatencyEntry{
		LastObservedLatencyMs: latencyMs,
		LastObservedAt:        orNow(observedAt),
	}
}

// drainLatencies returns and clears the pending latency map. Sparse map
// semantics per design §4.2: only checks that produced an observation
// since the previous heartbeat appear.
func (r *Runner) drainLatencies() map[string]transport.LatencyEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.latencies
	r.latencies = map[string]transport.LatencyEntry{}
	return out
}

// SendHeartbeat performs one heartbeat. Per design §4.2 there is no retry
// on failure — the next tick is the retry. The caller (the heartbeat
// ticker) drives cadence; this method just executes one request and
// applies any returned config updates.
//
// Returns the response (so callers can plumb config refresh) plus the
// transport error. ErrLighthouseGone bubbles up so main can exit cleanly.
func (r *Runner) SendHeartbeat(ctx context.Context) (*transport.HeartbeatResponse, error) {
	r.mu.Lock()
	etag := r.etag
	r.mu.Unlock()

	resp, err := r.client.Heartbeat(ctx, transport.HeartbeatRequest{
		AgentVersion:   AgentVersion,
		ConfigEtag:     etag,
		CheckLatencies: r.drainLatencies(),
	})
	if err != nil {
		return nil, err
	}
	// Server may rotate the etag — adopt it so subsequent heartbeats can
	// short-circuit.
	r.SetEtag(resp.ConfigEtag)
	// Per design §4.2: presence of `checks` signals "the server's config
	// view changed; update yours". flap_protection_threshold and paused
	// always come back, so the runner's view of those tracks the server's
	// at every heartbeat (cheap to apply, no churn when unchanged).
	var added []CheckDefinition
	if resp.Checks != nil {
		added = r.ApplyConfig(CheckDefsFromTransport(resp.Checks), resp.FlapProtectionThreshold, resp.Paused)
	} else {
		r.applyFlapAndPaused(resp.FlapProtectionThreshold, resp.Paused)
	}
	// Reconcile state with the server. RequestFullResync wins (re-emit for
	// every check); otherwise just initial-sync the newly-added checks so
	// they get their first event (without this they're stuck because the
	// flap tracker treats them as committed-state-unknown indefinitely).
	// Done in a goroutine so the heartbeat tick stays fast — agents may
	// have many checks and observations can take seconds.
	if resp.RequestFullResync {
		defs := r.Checks()
		go r.runResync(ctx, defs, "request_full_resync")
	} else if len(added) > 0 {
		go r.runResync(ctx, added, "new_checks")
	}
	return resp, nil
}

// runResync runs an initial-sync batch for the given subset of checks.
// Best-effort: failures log and drop. The next heartbeat (which sets
// the resync flag again on the server when needed) will retry.
func (r *Runner) runResync(ctx context.Context, defs []CheckDefinition, reason string) {
	if len(defs) == 0 {
		return
	}
	if err := r.RunInitialSync(ctx, defs); err != nil {
		slog.Warn("resync failed; will retry on next trigger",
			"reason", reason, "checks", len(defs), "error", err)
	}
}

func (r *Runner) applyFlapAndPaused(flapThreshold int, paused bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flap.SetThreshold(flapThreshold)
	r.paused = paused
}

// ObserveAndEmit runs a single check and emits a transition event when its
// state differs from the last committed state — debounced through the
// flap tracker (per design §7.4). Recurring observations of the same
// state are silent (edge-triggered, §3.2).
//
// Latency is recorded on every observation regardless of whether a
// transition fired — the heartbeat rollup is independent of transitions.
func (r *Runner) ObserveAndEmit(ctx context.Context, def CheckDefinition) error {
	obs := r.executor.Run(ctx, def)
	r.recordLatency(def.ID, obs.ResponseTimeMs, obs.ObservedAt)

	r.mu.Lock()
	prev, hadPrev := r.state[def.ID]
	commit := r.flap.Observe(def.ID, prev, hadPrev, obs.State)
	if commit {
		r.state[def.ID] = obs.State
	}
	r.mu.Unlock()

	if !commit {
		return nil
	}
	if !hadPrev {
		// Defensive: flap tracker shouldn't return commit=true without a
		// committed state, but if it ever does we don't have a prev_state
		// to send — initial-sync handles first observation.
		return nil
	}

	prevStr := string(prev)
	ev := transport.EventInput{
		CheckID:         def.ID,
		PrevState:       &prevStr,
		NewState:        string(obs.State),
		AgentObservedAt: orNow(obs.ObservedAt),
	}
	if obs.ResponseTimeMs > 0 {
		ev.ResponseTimeMs = ptr(obs.ResponseTimeMs)
	}
	if obs.StatusCode > 0 {
		ev.StatusCode = ptr(obs.StatusCode)
	}
	if obs.ErrorMessage != "" {
		ev.ErrorMessage = ptr(obs.ErrorMessage)
	}
	_, err := r.client.SendEvents(ctx, transport.EventsRequest{
		IsInitialSync: false,
		Events:        []transport.EventInput{ev},
	})
	return err
}

// AgentVersion is reported on every register / heartbeat. Linker-overridable
// at build time via -ldflags "-X github.com/statusharbor/lighthouse/internal/agent.AgentVersion=v0.1.2".
var AgentVersion = "0.1.0-dev"

// SetBuffer attaches a disk-backed event buffer. When set:
//   - Failed event sends append to it (caller's responsibility — slice A6
//     buffer integration with retry policy lives in the scheduler in
//     subsequent slices).
//   - Shutdown drains it before posting /shutdown.
func (r *Runner) SetBuffer(b *EventBuffer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buffer = b
}

// SetHealthState attaches a HealthState the heartbeat loop will update on
// every successful Console round-trip. Optional — leave nil to disable
// the /healthz endpoints (e.g., bare-metal installs).
func (r *Runner) SetHealthState(h *HealthState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.health = h
}

// Shutdown is the orderly teardown path triggered by SIGTERM (cmd/lighthouse
// wires the signal). Per design §7.3 step 4-5:
//
//  1. Flush buffered events that survived a prior outage.
//  2. POST /shutdown so the offline watchdog skips us during its 60s grace.
//
// Best-effort throughout — every step's error is logged but the function
// always returns nil so main can continue to a clean exit. Pass a context
// with a small timeout (5s recommended per design).
func (r *Runner) Shutdown(ctx context.Context, reason string) error {
	r.mu.Lock()
	buf := r.buffer
	r.mu.Unlock()

	if buf != nil {
		queued, err := buf.Drain()
		if err != nil {
			// Buffer read failed — keep going; we'd rather miss a flush
			// than block shutdown.
			_ = err
		} else if len(queued) > 0 {
			_, _ = r.client.SendEvents(ctx, transport.EventsRequest{
				IsInitialSync: false,
				Events:        queued,
			})
		}
	}
	// Best-effort shutdown notification.
	_ = r.client.Shutdown(ctx, transport.ShutdownRequest{Reason: reason})
	return nil
}

// CheckDefsFromTransport translates the transport-layer check shape to the
// agent-internal one. Kept as a small helper so the runner test can build
// definitions without touching transport types.
func CheckDefsFromTransport(in []transport.CheckDef) []CheckDefinition {
	out := make([]CheckDefinition, len(in))
	for i, c := range in {
		out[i] = CheckDefinition{
			ID:                 c.ID,
			Type:               c.Type,
			Name:               c.Name,
			URL:                c.URL,
			Method:             c.Method,
			ExpectedStatusCode: c.ExpectedStatusCode,
			IntervalSeconds:    c.IntervalSeconds,
			TimeoutSeconds:     c.TimeoutSeconds,
			KeywordCheck:       c.KeywordCheck,
			KeywordPresent:     c.KeywordPresent,
		}
	}
	return out
}

func ptr[T any](v T) *T { return &v }

func orNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t
}
