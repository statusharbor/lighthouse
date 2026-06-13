package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

func TestRunHeartbeat_TicksUntilContextCancelled(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(transport.HeartbeatResponse{ConfigEtag: "x"})
	}))
	defer srv.Close()

	client := transport.NewClient(srv.URL, "lh_test", "")
	r := NewRunner(&Config{Token: "lh_test", Agent: AgentConfig{MaxConcurrentChecks: 1}}, client, &fakeExecutor{}, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	_ = r.RunHeartbeat(ctx, 50*time.Millisecond)

	if hits.Load() < 3 {
		t.Errorf("expected ≥3 heartbeats in 250ms with 50ms tick, got %d", hits.Load())
	}
}

func TestRunHeartbeat_ReturnsOnLighthouseGone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"deleted"}`, http.StatusGone)
	}))
	defer srv.Close()

	client := transport.NewClient(srv.URL, "lh_test", "")
	r := NewRunner(&Config{Token: "lh_test"}, client, &fakeExecutor{}, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err := r.RunHeartbeat(ctx, 30*time.Millisecond)
	if err == nil {
		t.Error("expected ErrLighthouseGone, got nil")
	}
}

func TestRunHeartbeat_TransientErrorsAreSwallowed(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			// First call fails — simulate transient outage.
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(transport.HeartbeatResponse{ConfigEtag: "x"})
	}))
	defer srv.Close()

	client := transport.NewClient(srv.URL, "lh_test", "")
	r := NewRunner(&Config{Token: "lh_test"}, client, &fakeExecutor{}, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := r.RunHeartbeat(ctx, 30*time.Millisecond); err != nil {
		t.Errorf("transient 500 must not abort the heartbeat loop, got %v", err)
	}
	if hits.Load() < 3 {
		t.Errorf("loop should have continued past first failure; hits = %d", hits.Load())
	}
}

func TestRunScheduler_ExecutesEachCheckPeriodically(t *testing.T) {
	// The scheduler clamps intervals to minCheckIntervalFloor (5s in
	// production); shrink it here so the test can use a 1s tick without
	// waiting for the floor.
	prevFloor := minCheckIntervalFloor
	minCheckIntervalFloor = 100 * time.Millisecond
	t.Cleanup(func() { minCheckIntervalFloor = prevFloor })

	var eventCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/lighthouse/v1/events":
			eventCount.Add(1)
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(transport.EventsResponse{Received: 1})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	exec := &countingExecutor{}
	client := transport.NewClient(srv.URL, "lh_test", "")
	r := NewRunner(&Config{Token: "lh_test", Agent: AgentConfig{MaxConcurrentChecks: 5}}, client, exec, "", "")
	r.ApplyConfig([]CheckDefinition{
		{ID: "c1", IntervalSeconds: 1}, // 1s minimum from JSON cast (we'll override jitter via short interval)
	}, 1, false)

	// Pre-seed committed state so the first observation is "no transition" and
	// silent — we're testing scheduling, not transitions.
	r.commit("c1", StateUp)

	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	_ = r.RunScheduler(ctx)

	got := exec.calls.Load()
	if got < 1 {
		t.Errorf("expected ≥1 executor call (initial tick after jitter), got %d", got)
	}
}

// countingExecutor returns up state and counts calls.
type countingExecutor struct {
	calls atomic.Int32
}

func (c *countingExecutor) Run(_ context.Context, _ CheckDefinition) CheckObservation {
	c.calls.Add(1)
	return CheckObservation{State: StateUp}
}

// recordingExecutor captures the full CheckDefinition observed on every
// invocation. Used to assert the supervisor restarted a goroutine with
// the fresh def after ApplyConfig — without the restart, the executor
// would see only the original def forever (captured by value in
// runCheckLoop).
type recordingExecutor struct {
	mu   sync.Mutex
	seen []CheckDefinition
}

func (rec *recordingExecutor) Run(_ context.Context, def CheckDefinition) CheckObservation {
	rec.mu.Lock()
	rec.seen = append(rec.seen, def)
	rec.mu.Unlock()
	return CheckObservation{State: StateUp}
}

func (rec *recordingExecutor) Seen() []CheckDefinition {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	out := make([]CheckDefinition, len(rec.seen))
	copy(out, rec.seen)
	return out
}

// When a check's definition changes (interval, keyword, headers — any
// field), the supervisor must cancel the running goroutine and respawn
// it with the fresh def. Without this, the per-check goroutine keeps
// using the def it captured at startup and ignores ApplyConfig forever.
//
// Drives the cycle by changing KeywordCheck across two ApplyConfig calls
// and asserting both values appear in the executor's history.
func TestRunScheduler_RestartsGoroutineOnDefinitionChange(t *testing.T) {
	prevTick := supervisorTickInterval
	supervisorTickInterval = 25 * time.Millisecond
	t.Cleanup(func() { supervisorTickInterval = prevTick })

	prevFloor := minCheckIntervalFloor
	minCheckIntervalFloor = 100 * time.Millisecond
	t.Cleanup(func() { minCheckIntervalFloor = prevFloor })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/lighthouse/v1/events" {
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(transport.EventsResponse{Received: 1})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	rec := &recordingExecutor{}
	client := transport.NewClient(srv.URL, "lh_test", "")
	r := NewRunner(&Config{Token: "lh_test", Agent: AgentConfig{MaxConcurrentChecks: 5}}, client, rec, "", "")
	r.ApplyConfig([]CheckDefinition{
		{ID: "c1", Type: "http", IntervalSeconds: 1, KeywordCheck: "first"},
	}, 1, false)
	r.commit("c1", StateUp)

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = r.RunScheduler(ctx)
		close(done)
	}()

	// Wait for the initial tick to fire under the original def.
	if !waitFor(500*time.Millisecond, func() bool {
		for _, def := range rec.Seen() {
			if def.KeywordCheck == "first" {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("first def never observed; seen = %+v", rec.Seen())
	}

	// Mutate the def. Same ID; KeywordCheck flips to "second".
	r.ApplyConfig([]CheckDefinition{
		{ID: "c1", Type: "http", IntervalSeconds: 1, KeywordCheck: "second"},
	}, 1, false)

	// Supervisor tick (≤25ms) restarts the goroutine, which fires its
	// initial tick under the new def.
	if !waitFor(800*time.Millisecond, func() bool {
		for _, def := range rec.Seen() {
			if def.KeywordCheck == "second" {
				return true
			}
		}
		return false
	}) {
		t.Errorf("post-restart def never observed; supervisor failed to pick up def change. seen = %+v", rec.Seen())
	}

	cancel()
	<-done
}

// Defense-in-depth: even if a misconfigured server (or hand-crafted DB
// row) sends an interval below the floor, the agent must clamp instead
// of pounding the target every fraction of a second. Resolution lives
// in resolveCheckInterval (called once per goroutine spawn in
// runCheckLoop); test the helper directly so the assertion isn't tied
// to wall-clock ticker timing.
func TestResolveCheckInterval(t *testing.T) {
	prevFloor := minCheckIntervalFloor
	minCheckIntervalFloor = 5 * time.Second
	t.Cleanup(func() { minCheckIntervalFloor = prevFloor })

	cases := []struct {
		name     string
		input    int
		want     time.Duration
	}{
		{"zero falls back to 60s", 0, 60 * time.Second},
		{"negative falls back to 60s", -3, 60 * time.Second},
		{"below floor clamps to floor", 1, 5 * time.Second},
		{"floor passes through", 5, 5 * time.Second},
		{"above floor passes through", 30, 30 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveCheckInterval("c1", tc.input)
			if got != tc.want {
				t.Errorf("resolveCheckInterval(%d) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
