package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// fakeExecutor returns canned observations keyed by check id. The runner
// has no idea — it just calls Run for each definition in turn.
type fakeExecutor struct {
	out map[string]CheckObservation
	// Ordered record of which checks were invoked, in call order.
	calls []string
}

func (f *fakeExecutor) Run(_ context.Context, def CheckDefinition) CheckObservation {
	f.calls = append(f.calls, def.ID)
	return f.out[def.ID]
}

// recordingMockServer captures the request bodies hitting /events.
type recordingMockServer struct {
	*httptest.Server
	eventBatches []transport.EventsRequest
}

func newRecordingMock(t *testing.T) *recordingMockServer {
	t.Helper()
	m := &recordingMockServer{}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/lighthouse/v1/events" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		var req transport.EventsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		m.eventBatches = append(m.eventBatches, req)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(transport.EventsResponse{Received: len(req.Events)})
	}))
	t.Cleanup(m.Close)
	return m
}

func TestRunInitialSync_OneEventPerCheck_PrevStateNil(t *testing.T) {
	mock := newRecordingMock(t)
	client := transport.NewClient(mock.URL, "lh_test")
	exec := &fakeExecutor{
		out: map[string]CheckObservation{
			"c1": {State: StateUp, ResponseTimeMs: 42, StatusCode: 200},
			"c2": {State: StateDown, ResponseTimeMs: 5021, ErrorMessage: "i/o timeout"},
		},
	}
	r := NewRunner(&Config{Token: "lh_test"}, client, exec)

	defs := []CheckDefinition{
		{ID: "c1", Type: "http", Name: "api"},
		{ID: "c2", Type: "tcp", Name: "db"},
	}
	if err := r.RunInitialSync(context.Background(), defs); err != nil {
		t.Fatalf("RunInitialSync: %v", err)
	}

	if len(mock.eventBatches) != 1 {
		t.Fatalf("expected 1 batch posted, got %d", len(mock.eventBatches))
	}
	batch := mock.eventBatches[0]
	if batch.SyncKind != "initial" {
		t.Errorf("expected sync_kind=initial, got %q", batch.SyncKind)
	}
	if len(batch.Events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(batch.Events))
	}
	for _, ev := range batch.Events {
		if ev.PrevState != nil {
			t.Errorf("event[%s].PrevState must be nil for initial sync, got %v", ev.CheckID, *ev.PrevState)
		}
	}

	// Find c1 — should be up with 200 status code passed through.
	var c1 *transport.EventInput
	for i := range batch.Events {
		if batch.Events[i].CheckID == "c1" {
			c1 = &batch.Events[i]
		}
	}
	if c1 == nil || c1.NewState != "up" {
		t.Fatalf("c1 missing or wrong state: %+v", c1)
	}
	if c1.StatusCode == nil || *c1.StatusCode != 200 {
		t.Errorf("c1.StatusCode = %v, want 200", c1.StatusCode)
	}
	if c1.ResponseTimeMs == nil || *c1.ResponseTimeMs != 42 {
		t.Errorf("c1.ResponseTimeMs = %v, want 42", c1.ResponseTimeMs)
	}
}

func TestRunInitialSync_RunsEveryCheckExactlyOnce(t *testing.T) {
	mock := newRecordingMock(t)
	client := transport.NewClient(mock.URL, "lh_test")
	exec := &fakeExecutor{out: map[string]CheckObservation{
		"c1": {State: StateUp},
		"c2": {State: StateUp},
		"c3": {State: StateDown},
	}}
	r := NewRunner(&Config{Token: "lh_test"}, client, exec)

	defs := []CheckDefinition{{ID: "c1"}, {ID: "c2"}, {ID: "c3"}}
	if err := r.RunInitialSync(context.Background(), defs); err != nil {
		t.Fatal(err)
	}

	if len(exec.calls) != 3 {
		t.Errorf("expected 3 executor calls, got %d", len(exec.calls))
	}
	// State map should reflect every check's outcome.
	state := r.State()
	if state["c1"] != StateUp || state["c3"] != StateDown {
		t.Errorf("state not committed correctly: %+v", state)
	}
}

func TestRunInitialSync_NoChecks_NoNetworkCall(t *testing.T) {
	mock := newRecordingMock(t)
	client := transport.NewClient(mock.URL, "lh_test")
	r := NewRunner(&Config{Token: "lh_test"}, client, &fakeExecutor{})

	if err := r.RunInitialSync(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(mock.eventBatches) != 0 {
		t.Errorf("no checks → no batches; got %d", len(mock.eventBatches))
	}
}

// recordingFullMock captures requests on both /events and /heartbeat.
// Goroutine-safe: the agent's resync path posts events from a goroutine
// concurrent with the test reading the slice, so all field access goes
// through mu.
type recordingFullMock struct {
	*httptest.Server
	mu           sync.Mutex
	heartbeats   []transport.HeartbeatRequest
	eventBatches []transport.EventsRequest

	// What heartbeat responses to send (popped from front; falls back to
	// a default when empty).
	heartbeatResp []transport.HeartbeatResponse
}

func (m *recordingFullMock) EventBatches() []transport.EventsRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]transport.EventsRequest, len(m.eventBatches))
	copy(out, m.eventBatches)
	return out
}

func (m *recordingFullMock) Heartbeats() []transport.HeartbeatRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]transport.HeartbeatRequest, len(m.heartbeats))
	copy(out, m.heartbeats)
	return out
}

func newFullMock(t *testing.T) *recordingFullMock {
	t.Helper()
	m := &recordingFullMock{}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/lighthouse/v1/heartbeat":
			var req transport.HeartbeatRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			m.mu.Lock()
			m.heartbeats = append(m.heartbeats, req)
			resp := transport.HeartbeatResponse{ConfigEtag: "etag-default"}
			if len(m.heartbeatResp) > 0 {
				resp = m.heartbeatResp[0]
				m.heartbeatResp = m.heartbeatResp[1:]
			}
			m.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		case "/api/lighthouse/v1/events":
			var req transport.EventsRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			m.mu.Lock()
			m.eventBatches = append(m.eventBatches, req)
			m.mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(transport.EventsResponse{Received: len(req.Events)})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.Close)
	return m
}

func TestSendHeartbeat_IncludesEtagAndDrainsLatencies(t *testing.T) {
	mock := newFullMock(t)
	mock.heartbeatResp = []transport.HeartbeatResponse{{ConfigEtag: "new-etag"}}
	client := transport.NewClient(mock.URL, "lh_test")
	r := NewRunner(&Config{Token: "lh_test"}, client, &fakeExecutor{})
	r.SetEtag("old-etag")
	r.latency.record("c1", transport.LatencyEntry{LastObservedLatencyMs: 42})

	resp, err := r.SendHeartbeat(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.ConfigEtag != "new-etag" {
		t.Errorf("ConfigEtag returned = %q", resp.ConfigEtag)
	}
	if len(mock.heartbeats) != 1 {
		t.Fatalf("expected 1 heartbeat sent, got %d", len(mock.heartbeats))
	}
	hb := mock.heartbeats[0]
	if hb.ConfigEtag != "old-etag" {
		t.Errorf("sent etag = %q, want old-etag", hb.ConfigEtag)
	}
	if hb.CheckLatencies["c1"].LastObservedLatencyMs != 42 {
		t.Errorf("latency not sent: %+v", hb.CheckLatencies)
	}

	// The runner must have adopted the new etag.
	r.mu.Lock()
	got := r.etag
	r.mu.Unlock()
	if got != "new-etag" {
		t.Errorf("runner.etag = %q, want new-etag", got)
	}

	// Second heartbeat must NOT re-send the drained latency.
	if _, err := r.SendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(mock.heartbeats[1].CheckLatencies) != 0 {
		t.Errorf("latency map should be drained between heartbeats, got %+v", mock.heartbeats[1].CheckLatencies)
	}
}

func TestObserveAndEmit_SilentOnSteadyState(t *testing.T) {
	mock := newFullMock(t)
	client := transport.NewClient(mock.URL, "lh_test")
	exec := &fakeExecutor{out: map[string]CheckObservation{
		"c1": {State: StateUp, ResponseTimeMs: 10},
	}}
	r := NewRunner(&Config{Token: "lh_test"}, client, exec)

	// Seed initial state via initial-sync (one batch posted).
	if err := r.RunInitialSync(context.Background(), []CheckDefinition{{ID: "c1"}}); err != nil {
		t.Fatal(err)
	}
	if len(mock.eventBatches) != 1 {
		t.Fatalf("expected initial-sync batch, got %d", len(mock.eventBatches))
	}

	// Run again — same state, silent.
	if err := r.ObserveAndEmit(context.Background(), CheckDefinition{ID: "c1"}); err != nil {
		t.Fatal(err)
	}
	if err := r.ObserveAndEmit(context.Background(), CheckDefinition{ID: "c1"}); err != nil {
		t.Fatal(err)
	}
	if len(mock.eventBatches) != 1 {
		t.Errorf("steady state must not emit; expected 1 batch (initial), got %d", len(mock.eventBatches))
	}
}

func TestObserveAndEmit_EmitsTransitionWithPrevState(t *testing.T) {
	mock := newFullMock(t)
	client := transport.NewClient(mock.URL, "lh_test")
	exec := &fakeExecutor{out: map[string]CheckObservation{
		"c1": {State: StateUp},
	}}
	r := NewRunner(&Config{Token: "lh_test"}, client, exec)

	if err := r.RunInitialSync(context.Background(), []CheckDefinition{{ID: "c1"}}); err != nil {
		t.Fatal(err)
	}

	// Flip to down.
	exec.out["c1"] = CheckObservation{State: StateDown, ErrorMessage: "i/o timeout"}
	if err := r.ObserveAndEmit(context.Background(), CheckDefinition{ID: "c1"}); err != nil {
		t.Fatal(err)
	}

	if len(mock.eventBatches) != 2 {
		t.Fatalf("expected 2 batches, got %d", len(mock.eventBatches))
	}
	transitionBatch := mock.eventBatches[1]
	if transitionBatch.SyncKind != "" {
		t.Errorf("transition batch must have SyncKind=\"\", got %q", transitionBatch.SyncKind)
	}
	if len(transitionBatch.Events) != 1 {
		t.Fatalf("len(events) = %d", len(transitionBatch.Events))
	}
	ev := transitionBatch.Events[0]
	if ev.PrevState == nil || *ev.PrevState != "up" {
		t.Errorf("PrevState = %v, want \"up\"", ev.PrevState)
	}
	if ev.NewState != "down" {
		t.Errorf("NewState = %q, want \"down\"", ev.NewState)
	}
	if ev.ErrorMessage == nil || *ev.ErrorMessage != "i/o timeout" {
		t.Errorf("ErrorMessage = %v", ev.ErrorMessage)
	}
}

func TestObserveAndEmit_RecordsLatencyEvenWithoutTransition(t *testing.T) {
	mock := newFullMock(t)
	client := transport.NewClient(mock.URL, "lh_test")
	exec := &fakeExecutor{out: map[string]CheckObservation{
		"c1": {State: StateUp, ResponseTimeMs: 99},
	}}
	r := NewRunner(&Config{Token: "lh_test"}, client, exec)

	_ = r.RunInitialSync(context.Background(), []CheckDefinition{{ID: "c1"}})
	// Steady-state run — no transition, but latency must be recorded for
	// the next heartbeat.
	if err := r.ObserveAndEmit(context.Background(), CheckDefinition{ID: "c1"}); err != nil {
		t.Fatal(err)
	}
	if got := r.latency.drain()["c1"].LastObservedLatencyMs; got != 99 {
		t.Errorf("latency not recorded: got %d", got)
	}
}

func TestSendHeartbeat_ChecksPresent_AdoptsFreshConfig(t *testing.T) {
	mock := newFullMock(t)
	mock.heartbeatResp = []transport.HeartbeatResponse{{
		ConfigEtag:              "new-etag",
		Paused:                  true,
		FlapProtectionThreshold: 3,
		Checks: []transport.CheckDef{
			{ID: "c-new", Type: "http", Name: "fresh", IntervalSeconds: 60},
		},
	}}
	client := transport.NewClient(mock.URL, "lh_test")
	r := NewRunner(&Config{Token: "lh_test"}, client, &fakeExecutor{})

	if _, err := r.SendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}

	checks := r.Checks()
	if len(checks) != 1 || checks[0].ID != "c-new" {
		t.Errorf("Checks = %+v, want one entry id=c-new", checks)
	}
	if !r.IsPaused() {
		t.Error("IsPaused should be true after server reports paused")
	}
	r.mu.Lock()
	gotThreshold := r.flap.threshold
	r.mu.Unlock()
	if gotThreshold != 3 {
		t.Errorf("flap threshold = %d, want 3", gotThreshold)
	}
}

func TestSendHeartbeat_NoChecks_StillUpdatesPausedAndThreshold(t *testing.T) {
	mock := newFullMock(t)
	mock.heartbeatResp = []transport.HeartbeatResponse{{
		ConfigEtag:              "same-etag",
		Paused:                  true,
		FlapProtectionThreshold: 5,
		// Checks omitted — server says "your view of config is current".
	}}
	client := transport.NewClient(mock.URL, "lh_test")
	r := NewRunner(&Config{Token: "lh_test"}, client, &fakeExecutor{})
	r.ApplyConfig([]CheckDefinition{{ID: "kept"}}, 1, false)

	if _, err := r.SendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Existing checks preserved.
	checks := r.Checks()
	if len(checks) != 1 || checks[0].ID != "kept" {
		t.Errorf("checks list should be preserved when server omits it; got %+v", checks)
	}
	// But paused + threshold updated.
	if !r.IsPaused() {
		t.Error("IsPaused should track server's view")
	}
	r.mu.Lock()
	gotThreshold := r.flap.threshold
	r.mu.Unlock()
	if gotThreshold != 5 {
		t.Errorf("flap threshold = %d, want 5", gotThreshold)
	}
}

// ApplyConfig must report which check IDs are new vs already-present so the
// heartbeat path can initial-sync only the new ones.
func TestApplyConfig_ReturnsNewlyAddedChecks(t *testing.T) {
	r := NewRunner(&Config{Token: "x"}, nil, &fakeExecutor{})

	added := r.ApplyConfig([]CheckDefinition{{ID: "a"}, {ID: "b"}}, 1, false)
	if len(added) != 2 {
		t.Fatalf("first ApplyConfig: added = %d, want 2 (everything is new on first call)", len(added))
	}

	added = r.ApplyConfig([]CheckDefinition{{ID: "a"}, {ID: "b"}, {ID: "c"}}, 1, false)
	if len(added) != 1 || added[0].ID != "c" {
		t.Errorf("second ApplyConfig: added = %+v, want [{c}]", added)
	}

	// Removing a check is not considered "added".
	added = r.ApplyConfig([]CheckDefinition{{ID: "a"}}, 1, false)
	if len(added) != 0 {
		t.Errorf("removal-only ApplyConfig: added = %+v, want empty", added)
	}
}

// New checks arriving via heartbeat must trigger an initial-sync — without
// it the agent never seeds r.state for them and ObserveAndEmit silently
// drops every observation forever (see flap.Observe / hadPrev guard).
func TestSendHeartbeat_NewChecks_TriggerInitialSync(t *testing.T) {
	mock := newFullMock(t)
	mock.heartbeatResp = []transport.HeartbeatResponse{{
		ConfigEtag:              "new-etag",
		FlapProtectionThreshold: 1,
		Checks: []transport.CheckDef{
			{ID: "c-new", Type: "http", Name: "fresh", IntervalSeconds: 60},
		},
	}}
	client := transport.NewClient(mock.URL, "lh_test")
	exec := &fakeExecutor{out: map[string]CheckObservation{
		"c-new": {State: StateUp, ResponseTimeMs: 12, StatusCode: 200},
	}}
	r := NewRunner(&Config{Token: "lh_test"}, client, exec)

	if _, err := r.SendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Resync goroutine runs async; wait briefly.
	if !waitFor(200*time.Millisecond, func() bool {
		return len(mock.EventBatches()) >= 1
	}) {
		t.Fatalf("expected an initial-sync batch for the new check; eventBatches=%d", len(mock.EventBatches()))
	}

	batches := mock.EventBatches()
	batch := batches[0]
	if batch.SyncKind != "new_check" {
		t.Errorf("event batch sync_kind = %q, want new_check", batch.SyncKind)
	}
	if len(batch.Events) != 1 || batch.Events[0].CheckID != "c-new" {
		t.Errorf("event batch = %+v, want one event for c-new", batch.Events)
	}
}

// When the server sets request_full_resync=true, the agent must initial-sync
// EVERY current check, not just newly-added ones.
func TestSendHeartbeat_RequestFullResync_RunsForAllChecks(t *testing.T) {
	mock := newFullMock(t)
	mock.heartbeatResp = []transport.HeartbeatResponse{{
		ConfigEtag:              "etag-1",
		FlapProtectionThreshold: 1,
		RequestFullResync:       true,
		// No checks in the response (etag matches) — the runner already
		// has its checks list from a prior ApplyConfig.
	}}
	client := transport.NewClient(mock.URL, "lh_test")
	exec := &fakeExecutor{out: map[string]CheckObservation{
		"a": {State: StateUp, ResponseTimeMs: 5},
		"b": {State: StateDown, ErrorMessage: "timeout"},
	}}
	r := NewRunner(&Config{Token: "lh_test"}, client, exec)
	r.ApplyConfig([]CheckDefinition{{ID: "a"}, {ID: "b"}}, 1, false)

	if _, err := r.SendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}

	if !waitFor(200*time.Millisecond, func() bool {
		bs := mock.EventBatches()
		return len(bs) >= 1 && len(bs[0].Events) >= 2
	}) {
		t.Fatalf("expected initial-sync batch with 2 events; got batches=%+v", mock.EventBatches())
	}

	batch := mock.EventBatches()[0]
	if batch.SyncKind != "resync" {
		t.Errorf("sync_kind = %q, want resync", batch.SyncKind)
	}
	if len(batch.Events) != 2 {
		t.Errorf("events = %d, want 2 (one per current check)", len(batch.Events))
	}
}

// waitFor polls cond up to d. Returns true if cond ever true.
func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

func TestObserveAndEmit_FlapProtectionDelaysCommit(t *testing.T) {
	mock := newFullMock(t)
	client := transport.NewClient(mock.URL, "lh_test")
	exec := &fakeExecutor{out: map[string]CheckObservation{
		"c1": {State: StateUp},
	}}
	r := NewRunner(&Config{Token: "lh_test"}, client, exec)
	r.ApplyConfig(nil, 3, false) // threshold = 3

	// Initial sync → committed: up
	_ = r.RunInitialSync(context.Background(), []CheckDefinition{{ID: "c1"}})

	// Flip executor to "down" — first two should be silent, third commits.
	exec.out["c1"] = CheckObservation{State: StateDown}
	for range 2 {
		_ = r.ObserveAndEmit(context.Background(), CheckDefinition{ID: "c1"})
	}
	if len(mock.eventBatches) != 1 {
		t.Errorf("with threshold=3, first 2 differing observations must NOT emit; got %d batches (initial + ?)", len(mock.eventBatches))
	}

	// Third differing observation → commit + transition event.
	_ = r.ObserveAndEmit(context.Background(), CheckDefinition{ID: "c1"})
	if len(mock.eventBatches) != 2 {
		t.Errorf("3rd consecutive diff must emit; got %d batches", len(mock.eventBatches))
	}
	if r.State()["c1"] != StateDown {
		t.Errorf("state not committed after threshold reached: %+v", r.State())
	}
}

// recordingShutdownMock extends the full mock with /shutdown capture.
type recordingShutdownMock struct {
	*recordingFullMock
	shutdownCalls []transport.ShutdownRequest
}

func newShutdownMock(t *testing.T) *recordingShutdownMock {
	t.Helper()
	full := newFullMock(t)
	wrapper := &recordingShutdownMock{recordingFullMock: full}

	// Wrap the existing handler to also catch /shutdown.
	originalHandler := full.Config.Handler
	full.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/lighthouse/v1/shutdown" {
			var req transport.ShutdownRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			wrapper.shutdownCalls = append(wrapper.shutdownCalls, req)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		originalHandler.ServeHTTP(w, r)
	})
	return wrapper
}

func TestShutdown_FlushesBufferedEventsThenPostsShutdown(t *testing.T) {
	mock := newShutdownMock(t)
	client := transport.NewClient(mock.URL, "lh_test")
	r := NewRunner(&Config{Token: "lh_test"}, client, &fakeExecutor{})

	buf, err := NewEventBuffer(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := buf.Append([]transport.EventInput{
		{CheckID: "c1", NewState: "down", AgentObservedAt: time.Now().UTC()},
	}); err != nil {
		t.Fatal(err)
	}
	r.SetBuffer(buf)

	if err := r.Shutdown(context.Background(), "sigterm"); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// Flushed events should have been POSTed first.
	if len(mock.eventBatches) != 1 {
		t.Errorf("expected 1 events batch (the buffer flush), got %d", len(mock.eventBatches))
	} else if mock.eventBatches[0].SyncKind != "" {
		t.Errorf("buffer flush must have empty SyncKind, got %q", mock.eventBatches[0].SyncKind)
	}
	// Then /shutdown.
	if len(mock.shutdownCalls) != 1 {
		t.Fatalf("expected 1 shutdown call, got %d", len(mock.shutdownCalls))
	}
	if mock.shutdownCalls[0].Reason != "sigterm" {
		t.Errorf("Reason = %q", mock.shutdownCalls[0].Reason)
	}

	// Buffer must be drained on disk.
	empty, _ := buf.IsEmpty()
	if !empty {
		t.Error("buffer should be empty after shutdown drain")
	}
}

func TestShutdown_NoBufferStillPostsShutdown(t *testing.T) {
	mock := newShutdownMock(t)
	client := transport.NewClient(mock.URL, "lh_test")
	r := NewRunner(&Config{Token: "lh_test"}, client, &fakeExecutor{})

	if err := r.Shutdown(context.Background(), "sigterm"); err != nil {
		t.Fatal(err)
	}
	if len(mock.shutdownCalls) != 1 {
		t.Errorf("expected 1 shutdown call, got %d", len(mock.shutdownCalls))
	}
	if len(mock.eventBatches) != 0 {
		t.Errorf("no buffer → no events to flush; got %d batches", len(mock.eventBatches))
	}
}

func TestShutdown_BestEffort_NetworkErrorDoesNotPropagate(t *testing.T) {
	// Point at a non-listening port — Shutdown must still return nil so
	// main can proceed to exit cleanly.
	client := transport.NewClient("http://127.0.0.1:1", "lh_test")
	r := NewRunner(&Config{Token: "lh_test"}, client, &fakeExecutor{})

	if err := r.Shutdown(context.Background(), "sigterm"); err != nil {
		t.Errorf("Shutdown must be best-effort, got error: %v", err)
	}
}

func TestCheckDefsFromTransport(t *testing.T) {
	in := []transport.CheckDef{
		{ID: "x", Type: "http", URL: "https://e.com", IntervalSeconds: 60, TimeoutSeconds: 10},
		{ID: "d", Type: "dns", URL: "api.internal", IntervalSeconds: 300, TimeoutSeconds: 5,
			DNSRecordType: "A", DNSExpectedIPs: []string{"10.0.0.5"}, DNSResolver: "10.0.0.10:53"},
	}
	out := CheckDefsFromTransport(in)
	if len(out) != 2 {
		t.Fatalf("translation failed: %+v", out)
	}
	if out[0].URL != "https://e.com" || out[0].IntervalSeconds != 60 {
		t.Errorf("http def translation failed: %+v", out[0])
	}
	// The DNS-only fields must survive the transport → agent translation —
	// otherwise the agent receives a DNS check it cannot actually run.
	dns := out[1]
	if dns.DNSRecordType != "A" || dns.DNSResolver != "10.0.0.10:53" {
		t.Errorf("dns fields not translated: %+v", dns)
	}
	if len(dns.DNSExpectedIPs) != 1 || dns.DNSExpectedIPs[0] != "10.0.0.5" {
		t.Errorf("dns expected values not translated: %+v", dns.DNSExpectedIPs)
	}
}
