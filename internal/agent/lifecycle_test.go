package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	client := transport.NewClient(srv.URL, "lh_test")
	r := NewRunner(&Config{Token: "lh_test", Agent: AgentConfig{MaxConcurrentChecks: 1}}, client, &fakeExecutor{})

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

	client := transport.NewClient(srv.URL, "lh_test")
	r := NewRunner(&Config{Token: "lh_test"}, client, &fakeExecutor{})

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

	client := transport.NewClient(srv.URL, "lh_test")
	r := NewRunner(&Config{Token: "lh_test"}, client, &fakeExecutor{})

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
	client := transport.NewClient(srv.URL, "lh_test")
	r := NewRunner(&Config{Token: "lh_test", Agent: AgentConfig{MaxConcurrentChecks: 5}}, client, exec)
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
