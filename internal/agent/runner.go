package agent

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// Backoff schedule for sendEventsWithBuffer. Three attempts at
// 1s / 4s / 16s before falling back to the on-disk buffer. Total
// wall-clock = ~21s on the worst case — tight enough that a check
// ticking on a 30s interval doesn't queue up behind retries during
// a brief Console flake.
var eventsRetrySchedule = []time.Duration{
	1 * time.Second,
	4 * time.Second,
	16 * time.Second,
}

// degradedThreshold is the number of consecutive heartbeat failures
// after which sendEvents skips the network attempt and writes
// straight to the buffer. 3 ticks at the typical 15s interval = ~45s
// of confirmed downtime; past that point hammering the Console with
// per-transition retries is wasted work that just slows the agent
// down for no chance of delivery.
const degradedThreshold = 3

// Runner orchestrates the agent lifecycle: register, initial-sync,
// heartbeat ticker, edge-triggered transition emission, on-disk buffer
// for Console-outage survival, and graceful shutdown.
type Runner struct {
	cfg      *Config
	client   *transport.Client
	executor CheckExecutor

	// nodeName goes out on every heartbeat. Drives the Console's
	// lighthouse_active_agents table — one row per (lighthouse,
	// node_name) for per-pod liveness in multi-instance Lighthouses.
	// On k8s the value comes from the NODE_NAME downward-API env
	// var; on bare-metal it's the OS hostname.
	nodeName string

	// podHostname is the agent's own os.Hostname() — the DaemonSet
	// pod name on k8s, the StatefulSet pod name on the central role,
	// or the OS hostname on bare-metal. Paired with nodeName on the
	// heartbeat so the Console's Metrics page can render
	// "<node> (<pod>)" when the two differ. Empty in tests is fine:
	// Console treats empty as "no pod-vs-node distinction" and
	// falls back to displaying nodeName only.
	podHostname string

	// State tracked across the run — committed state per check_id used for
	// transition detection. mu guards state + etag; the rollups self-lock
	// (see rollup.go) so they run lock-free of state-transition commits.
	mu    sync.Mutex
	state map[string]State
	etag  string
	// latency + certExpiry: sparse per-check telemetry drained onto each heartbeat.
	latency    *rollup[transport.LatencyEntry]
	certExpiry *rollup[transport.CertExpiryEntry]
	buffer     *EventBuffer
	checks     []CheckDefinition
	flap       *flapTracker
	paused     bool
	health     *HealthState

	// degradedHeartbeats counts consecutive heartbeat failures. When
	// it hits degradedThreshold the runner enters degraded mode and
	// new transitions are routed straight to the disk buffer instead
	// of attempting the Console (which is demonstrably down). The
	// first successful heartbeat resets the counter to 0 + triggers
	// an immediate buffer drain. Atomic so the steady-state read
	// from sendEvents is lock-free.
	//
	// Lives on Runner (not in a sub-struct) because every event-send
	// path consults it and we want the read to be cheap.
	degradedHeartbeats atomic.Uint32

	// resyncWG tracks the fire-and-forget runResync goroutines
	// spawned from SendHeartbeat. Shutdown waits on this WG inside
	// its caller-provided budget so a SIGTERM mid-resync doesn't
	// strand transitions that were about to reach the buffer.
	resyncWG sync.WaitGroup
}

// NewRunner wires a Runner. The executor abstraction is what tests stub.
// nodeName goes out on every heartbeat (see Runner.nodeName comment);
// podHostname is os.Hostname() and lets the Console pair node-name
// with pod-name in the Metrics UI (see Runner.podHostname comment).
// Pass "" in tests that don't care about per-pod liveness or display —
// Console handles empty values as backwards-compatible no-ops.
func NewRunner(cfg *Config, client *transport.Client, executor CheckExecutor, nodeName, podHostname string) *Runner {
	return &Runner{
		cfg:         cfg,
		client:      client,
		executor:    executor,
		nodeName:    nodeName,
		podHostname: podHostname,
		state:       map[string]State{},
		latency:     newRollup[transport.LatencyEntry](),
		certExpiry:  newRollup[transport.CertExpiryEntry](),
		flap:        newFlapTracker(1), // threshold updated by Register/Heartbeat config
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

// SyncKind labels a sync batch sent to /events. Empty string is reserved
// for ordinary state-transition batches (sent by ObserveAndEmit, not by
// RunSync). Per design §3.2 Interpretation B + §4.3.
type SyncKind string

const (
	// SyncKindInitial is the agent-startup batch — every check observed
	// once.
	SyncKindInitial SyncKind = "initial"
	// SyncKindResync is the server-requested re-emit, fired when the
	// heartbeat response sets request_full_resync=true.
	SyncKindResync SyncKind = "resync"
	// SyncKindNewCheck is the agent-driven sync for checks that arrived
	// in a heartbeat response post-startup (initial sync only covers
	// boot-time checks).
	SyncKindNewCheck SyncKind = "new_check"
)

// RunSync performs one observation per check and POSTs them all as a
// single batch tagged with the given SyncKind. Per design §3.2
// Interpretation B: prev_state=NULL on every row, server applies "silent
// on up, fire on down" semantics.
func (r *Runner) RunSync(ctx context.Context, defs []CheckDefinition, kind SyncKind) error {
	events := make([]transport.EventInput, 0, len(defs))
	for _, def := range defs {
		obs := r.executor.Run(ctx, def)
		r.commit(def.ID, obs.State)

		ev := transport.EventInput{
			CheckID:         def.ID,
			PrevState:       nil, // sync sentinel — every kind has prev=NULL
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
	return r.sendEventsWithBuffer(ctx, transport.EventsRequest{
		SyncKind: string(kind),
		Events:   events,
	})
}

// sendEventsWithBuffer is the single entry point for all SendEvents
// calls. It implements the design §4.3 retry+buffer policy that the
// raw runtime previously skipped:
//
//  1. If we're in degraded mode (enough consecutive heartbeat
//     failures), skip the network and append directly to the buffer
//     — the next successful heartbeat will drain it.
//  2. Otherwise try SendEvents with 3 attempts and the documented
//     1s / 4s / 16s backoff.
//  3. If all attempts fail (or the buffer wasn't attached), append
//     to the buffer so a future drain can replay.
//
// Errors are LOGGED at warn level but never returned — the buffer
// IS the recovery path, and a caller seeing an error from this
// method would have nothing useful to do with it. Returning success
// when the network failed but the buffer accepted is honest: from
// the agent's contract perspective the transition is durable.
//
// Callers that explicitly need to know whether the network attempt
// succeeded (e.g., the shutdown path that wants to skip the
// final POST when the buffer is the better fallback) should call
// r.client.SendEvents directly.
func (r *Runner) sendEventsWithBuffer(ctx context.Context, req transport.EventsRequest) error {
	if len(req.Events) == 0 {
		return nil
	}

	// Degraded-mode short-circuit. Heartbeat has been failing;
	// don't burn 21s of backoff per transition just to fail again.
	// Drain happens immediately on the next successful heartbeat.
	if r.degradedHeartbeats.Load() >= degradedThreshold {
		return r.bufferEvents(req.Events, "degraded mode")
	}

	// Three-attempt retry with the documented backoff. ctx
	// cancellation aborts mid-attempt; on shutdown we'd rather
	// flush to buffer than block.
	var lastErr error
	for i, wait := range eventsRetrySchedule {
		_, err := r.client.SendEvents(ctx, req)
		if err == nil {
			return nil
		}
		if errors.Is(err, transport.ErrLighthouseGone) {
			// No retry — lighthouse is gone, agent should exit.
			// Shutdown() cares about this specific error so the
			// buffer doesn't accumulate junk for a dead
			// destination. Non-shutdown callers (RunScheduler →
			// ObserveAndEmit) treat it the same way and exit, so
			// the events in flight here ARE dropped on the floor.
			// Log it so the loss is visible in operator-side traces
			// when this happens for any other reason.
			slog.Warn("events dropped: lighthouse gone (agent will exit)",
				"events", len(req.Events))
			return err
		}
		lastErr = err
		// Don't sleep after the final attempt.
		if i == len(eventsRetrySchedule)-1 {
			break
		}
		select {
		case <-ctx.Done():
			return r.bufferEvents(req.Events, "ctx cancelled mid-retry")
		case <-time.After(wait):
		}
	}

	return r.bufferEvents(req.Events, lastErr.Error())
}

// bufferEvents appends to the on-disk buffer and logs at warn level.
// Returns nil even on buffer failure — losing events to a buffer
// error is the same failure class as losing them to a Console
// outage, and neither is something the caller can fix.
func (r *Runner) bufferEvents(events []transport.EventInput, reason string) error {
	r.mu.Lock()
	buf := r.buffer
	r.mu.Unlock()

	if buf == nil {
		slog.Warn("event send failed and no buffer attached; events dropped",
			"events", len(events), "reason", reason)
		return nil
	}
	if err := buf.Append(events); err != nil {
		slog.Warn("event send failed and buffer append also failed",
			"events", len(events), "reason", reason, "buffer_error", err)
		return nil
	}
	slog.Info("events buffered for later flush",
		"events", len(events), "reason", reason)
	return nil
}

// drainBuffer flushes any buffered events through SendEvents.
// Called from SendHeartbeat after a successful round-trip so the
// agent reconnects to the Console and immediately catches up.
//
// Best-effort: on partial failure the buffer is gone (Drain
// removes the file), so any send error here means transitions
// that survived the outage are lost. We tolerate this because:
//   - if the heartbeat just succeeded, the Console is back; a
//     SendEvents failure within seconds is unusual
//   - if it DOES fail, the next observed transitions will go
//     through sendEventsWithBuffer which re-creates the buffer
//   - exposing this error to the caller would force the heartbeat
//     loop to handle it, complicating the call site without
//     adding any recovery path
func (r *Runner) drainBuffer(ctx context.Context) {
	r.mu.Lock()
	buf := r.buffer
	r.mu.Unlock()
	if buf == nil {
		return
	}
	queued, err := buf.Drain()
	if err != nil {
		slog.Warn("buffer drain failed", "error", err)
		return
	}
	if len(queued) == 0 {
		return
	}
	if _, err := r.client.SendEvents(ctx, transport.EventsRequest{
		// SyncKind="" — buffered transitions, not a sync batch.
		Events: queued,
	}); err != nil {
		// Re-append on send failure so the next heartbeat retries.
		// This keeps the "no transition is lost on a single
		// network blip" guarantee even when the buffer was
		// non-empty going into the failed send.
		if appErr := buf.Append(queued); appErr != nil {
			slog.Warn("buffered events lost after drain send failed and re-append failed",
				"events", len(queued), "send_error", err, "append_error", appErr)
		}
		return
	}
	slog.Info("buffered events flushed after Console recovered",
		"events", len(queued))
}

// RunInitialSync is the boot-time sync (calls RunSync with
// SyncKindInitial). Kept as a named entry point because main.go reads
// nicely with it.
func (r *Runner) RunInitialSync(ctx context.Context, defs []CheckDefinition) error {
	return r.RunSync(ctx, defs, SyncKindInitial)
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

// SendHeartbeat performs one heartbeat. Per design §4.2 there is no retry
// on failure — the next tick is the retry. The caller (the heartbeat
// ticker) drives cadence; this method just executes one request and
// applies any returned config updates.
//
// Side effects on success:
//   - degradedHeartbeats counter resets to 0 (A3)
//   - if a buffer is attached AND was non-empty, drainBuffer fires
//     synchronously so the recovered Console catches up before the
//     next observation produces a fresh transition (A1)
//
// On failure:
//   - degradedHeartbeats increments (A3); when it crosses
//     degradedThreshold, sendEventsWithBuffer starts skipping the
//     network and going straight to the buffer
//
// Returns the response (so callers can plumb config refresh) plus the
// transport error. ErrLighthouseGone bubbles up so main can exit cleanly.
func (r *Runner) SendHeartbeat(ctx context.Context) (*transport.HeartbeatResponse, error) {
	r.mu.Lock()
	etag := r.etag
	r.mu.Unlock()

	// Role goes out on every heartbeat alongside NodeName so the Console
	// can label the central pod separately from per-node reporters in
	// its "Active agents" panel. Defaults to "central" when the role
	// field is empty (older config OR a bare-metal install that never
	// set LIGHTHOUSE_ROLE), since on bare-metal the only agent IS the
	// central one — preserves backwards compatibility with rows that
	// landed before this column existed.
	role := r.cfg.Agent.Role
	if role == "" {
		role = RoleCentral
	}

	resp, err := r.client.Heartbeat(ctx, transport.HeartbeatRequest{
		AgentVersion:   AgentVersion,
		ConfigEtag:     etag,
		CheckLatencies: r.latency.drain(),
		CertExpiry:     r.certExpiry.drain(),
		NodeName:       r.nodeName,
		Role:           role,
		PodHostname:    r.podHostname,
	})
	if err != nil {
		// Bump degraded counter on every failure; the threshold
		// check inside sendEventsWithBuffer reads it lock-free.
		// ErrLighthouseGone still increments but the caller exits
		// before it matters.
		now := r.degradedHeartbeats.Add(1)
		if now == degradedThreshold {
			slog.Warn("agent entering degraded mode after consecutive heartbeat failures",
				"consecutive_failures", now,
				"threshold", degradedThreshold)
		}
		return nil, err
	}

	// Recovery path: reset the counter + drain. A clean transition
	// from "degraded for a while" back to "healthy" is the moment
	// we want to flush whatever the buffer accumulated during the
	// outage.
	if prev := r.degradedHeartbeats.Swap(0); prev >= degradedThreshold {
		slog.Info("agent exited degraded mode; draining buffer",
			"prior_consecutive_failures", prev)
	}
	r.drainBuffer(ctx)
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
		r.spawnResync(ctx, defs, SyncKindResync)
	} else if len(added) > 0 {
		r.spawnResync(ctx, added, SyncKindNewCheck)
	}
	return resp, nil
}

// spawnResync launches runResync in a goroutine tracked by resyncWG
// so Shutdown can drain it. Without the WG, a SIGTERM mid-resync
// would lose every transition the goroutine was about to feed
// through sendEventsWithBuffer — exactly the kind of "outage =
// silent data loss" failure the A1 buffer was designed to prevent.
func (r *Runner) spawnResync(ctx context.Context, defs []CheckDefinition, kind SyncKind) {
	if len(defs) == 0 {
		return
	}
	r.resyncWG.Add(1)
	go func() {
		defer r.resyncWG.Done()
		r.runResync(ctx, defs, kind)
	}()
}

// runResync runs a sync batch for the given subset of checks. Best-effort:
// failures log and drop. The next heartbeat (which sets the resync flag
// again on the server when needed) will retry.
//
// Routes through sendEventsWithBuffer (via RunSync) so a Console
// outage during a resync buffers transitions to disk instead of
// dropping them.
func (r *Runner) runResync(ctx context.Context, defs []CheckDefinition, kind SyncKind) {
	if len(defs) == 0 {
		return
	}
	if err := r.RunSync(ctx, defs, kind); err != nil {
		slog.Warn("resync failed; will retry on next trigger",
			"sync_kind", string(kind), "checks", len(defs), "error", err)
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
	r.latency.record(def.ID, transport.LatencyEntry{
		LastObservedLatencyMs: obs.ResponseTimeMs,
		LastObservedAt:        orNow(obs.ObservedAt),
	})
	// ssl checks carry a leaf-cert days-to-expiry whenever a cert was read
	// (valid or expired) — roll it up for the next heartbeat, independent
	// of any state transition.
	if obs.CertDaysToExpiry != nil {
		r.certExpiry.record(def.ID, transport.CertExpiryEntry{
			DaysToExpiry: *obs.CertDaysToExpiry,
			ObservedAt:   orNow(obs.ObservedAt),
		})
	}

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
	// Route through the retry+buffer wrapper so a Console outage
	// doesn't lose the transition (A1). In degraded mode this
	// short-circuits to the buffer directly.
	return r.sendEventsWithBuffer(ctx, transport.EventsRequest{
		// SyncKind="" — ordinary state transition.
		Events: []transport.EventInput{ev},
	})
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
	// Step 0: wait for any in-flight resync goroutines to finish so
	// their transitions reach the buffer before we drain it (A2).
	// resyncWG.Wait is unbounded by design — the caller's ctx
	// timeout (30s in cmd/lighthouse) is the wall-clock budget; if
	// the resyncs haven't completed within the parent budget, the
	// parent ctx cancels their in-flight HTTP and they exit
	// promptly via sendEventsWithBuffer's ctx-cancellation branch
	// (which routes the events to the buffer).
	resyncDrained := make(chan struct{})
	go func() {
		r.resyncWG.Wait()
		close(resyncDrained)
	}()
	select {
	case <-resyncDrained:
	case <-ctx.Done():
		slog.Warn("shutdown ctx ended before resync goroutines drained; in-flight transitions may have routed to buffer or been lost",
			"reason", reason)
	}

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
			// Try once via the Console. On failure re-append to the
			// buffer so the next agent restart picks them up. The
			// 1h staleness gate on Drain protects against zombie
			// events resurfacing after a long downtime.
			if _, err := r.client.SendEvents(ctx, transport.EventsRequest{
				// SyncKind="" — buffered transitions, not a sync batch.
				Events: queued,
			}); err != nil {
				if appErr := buf.Append(queued); appErr != nil {
					slog.Warn("shutdown flush failed and buffer re-append also failed",
						"events", len(queued),
						"send_error", err,
						"append_error", appErr)
				} else {
					slog.Warn("shutdown flush to Console failed; events re-queued for next agent restart",
						"events", len(queued), "send_error", err)
				}
			}
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
		def := CheckDefinition{
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
			RequestBody:        c.RequestBody,
			SkipTLSVerify:      c.SkipTLSVerify,
			DNSRecordType:      c.DNSRecordType,
			DNSExpectedIPs:     c.DNSExpectedIPs,
			DNSResolver:        c.DNSResolver,
		}
		for _, h := range c.RequestHeaders {
			def.RequestHeaders = append(def.RequestHeaders, HeaderPair{Key: h.Key, Value: h.Value})
		}
		for _, h := range c.ExpectedHeaders {
			def.ExpectedHeaders = append(def.ExpectedHeaders, ExpectedHeader{Key: h.Key, Value: h.Value, Match: h.Match})
		}
		out[i] = def
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
