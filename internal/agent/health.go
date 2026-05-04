package agent

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"
)

// DefaultHealthLivenessThreshold is the staleness window for /healthz/live.
// If the most-recent heartbeat is older than this, the agent is considered
// hung and Kubernetes liveness probes fail. Sized to allow ~3 missed
// heartbeats at the default 15s interval.
const DefaultHealthLivenessThreshold = 45 * time.Second

// HealthState tracks the liveness and readiness signals served by
// /healthz/{live,ready}. Safe for concurrent use.
type HealthState struct {
	lastHeartbeatUnixNano atomic.Int64
	ready                 atomic.Bool
	threshold             time.Duration
	now                   func() time.Time // injectable for tests
}

// NewHealthState constructs a HealthState. A zero or negative threshold
// falls back to DefaultHealthLivenessThreshold.
func NewHealthState(threshold time.Duration) *HealthState {
	if threshold <= 0 {
		threshold = DefaultHealthLivenessThreshold
	}
	return &HealthState{threshold: threshold, now: time.Now}
}

// RecordHeartbeat marks the most-recent successful heartbeat. Called by
// the heartbeat loop after every Console round-trip that didn't error.
func (h *HealthState) RecordHeartbeat() {
	h.lastHeartbeatUnixNano.Store(h.now().UnixNano())
}

// MarkReady flips the agent to ready (typically right after Register
// succeeds). Idempotent — readiness never flaps back on transient
// Console outages because the agent is still doing its job locally.
func (h *HealthState) MarkReady() {
	h.ready.Store(true)
}

// IsLive reports whether the last heartbeat is within the staleness
// threshold. Before the first heartbeat fires (lastHeartbeat == 0),
// returns true so kubelet doesn't kill the pod during startup.
func (h *HealthState) IsLive() bool {
	last := h.lastHeartbeatUnixNano.Load()
	if last == 0 {
		return true
	}
	return time.Duration(h.now().UnixNano()-last) <= h.threshold
}

// IsReady reports whether the agent has completed initial registration.
func (h *HealthState) IsReady() bool {
	return h.ready.Load()
}

// Handler returns an http.Handler exposing the probe endpoints.
func (h *HealthState) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz/live", func(w http.ResponseWriter, _ *http.Request) {
		if h.IsLive() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("stale heartbeat\n"))
	})
	mux.HandleFunc("/healthz/ready", func(w http.ResponseWriter, _ *http.Request) {
		if h.IsReady() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready\n"))
	})
	return mux
}

// RunServer starts an HTTP server on addr and blocks until ctx is
// cancelled or the server fails. Returns nil on graceful shutdown.
func (h *HealthState) RunServer(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
