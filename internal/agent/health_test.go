package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeClock returns a controllable clock; advance() bumps it.
type fakeClock struct{ now time.Time }

func (f *fakeClock) advance(d time.Duration) { f.now = f.now.Add(d) }
func (f *fakeClock) Now() time.Time          { return f.now }

func newFakeHealth(t *testing.T, threshold time.Duration) (*HealthState, *fakeClock) {
	t.Helper()
	clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	h := NewHealthState(threshold)
	h.now = clock.Now
	return h, clock
}

func TestHealthState_LiveBeforeFirstHeartbeat(t *testing.T) {
	h, _ := newFakeHealth(t, 45*time.Second)
	if !h.IsLive() {
		t.Fatal("must report live during bootstrap (no heartbeat yet)")
	}
}

func TestHealthState_LiveWithinThreshold(t *testing.T) {
	h, clock := newFakeHealth(t, 45*time.Second)
	h.RecordHeartbeat()
	clock.advance(44 * time.Second)
	if !h.IsLive() {
		t.Fatal("44s after heartbeat with 45s threshold should be live")
	}
}

func TestHealthState_StalePastThreshold(t *testing.T) {
	h, clock := newFakeHealth(t, 45*time.Second)
	h.RecordHeartbeat()
	clock.advance(46 * time.Second)
	if h.IsLive() {
		t.Fatal("46s after heartbeat with 45s threshold must be stale")
	}
}

func TestHealthState_ReadyOnlyAfterMark(t *testing.T) {
	h, _ := newFakeHealth(t, 45*time.Second)
	if h.IsReady() {
		t.Fatal("must not start ready")
	}
	h.MarkReady()
	if !h.IsReady() {
		t.Fatal("MarkReady should flip ready bit")
	}
}

func TestHealthState_DefaultThreshold(t *testing.T) {
	h := NewHealthState(0)
	if h.threshold != DefaultHealthLivenessThreshold {
		t.Errorf("zero threshold should fall back to default, got %v", h.threshold)
	}
}

func TestHealthState_HandlerLive(t *testing.T) {
	h, clock := newFakeHealth(t, 45*time.Second)
	h.RecordHeartbeat()
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz/live")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("live handler should return 200 within threshold, got %d", resp.StatusCode)
	}

	clock.advance(60 * time.Second)
	resp, err = http.Get(srv.URL + "/healthz/live")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("live handler should return 503 past threshold, got %d", resp.StatusCode)
	}
}

func TestHealthState_HandlerReady(t *testing.T) {
	h, _ := newFakeHealth(t, 45*time.Second)
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz/ready")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("ready handler should return 503 before MarkReady, got %d", resp.StatusCode)
	}

	h.MarkReady()
	resp, err = http.Get(srv.URL + "/healthz/ready")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ready handler should return 200 after MarkReady, got %d", resp.StatusCode)
	}
}
