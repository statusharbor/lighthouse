package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// httptest-based mock Console. Hermetic per design §10.2 (slice A1).

func newMockServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestRegister_HappyPath(t *testing.T) {
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/lighthouse/v1/register" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer lh_test" {
			t.Errorf("missing/wrong Authorization header: %q", r.Header.Get("Authorization"))
		}
		var got RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.AgentVersion != "0.1.0" || got.AgentHostname != "test-host" {
			t.Errorf("body = %+v", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(RegisterResponse{
			LighthouseID:             "lh-uuid",
			Name:                     "prod-vpc",
			Host:                     "test-host",
			HeartbeatIntervalSeconds: 15,
			FlapProtectionThreshold:  1,
			ConfigEtag:               "abc123",
			Checks:                   []CheckDef{},
		})
	})

	c := NewClient(srv.URL, "lh_test", "")
	resp, err := c.Register(context.Background(), RegisterRequest{
		AgentVersion:  "0.1.0",
		AgentHostname: "test-host",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.LighthouseID != "lh-uuid" {
		t.Errorf("LighthouseID = %q", resp.LighthouseID)
	}
	if resp.HeartbeatInterval().Seconds() != 15 {
		t.Errorf("HeartbeatInterval = %v", resp.HeartbeatInterval())
	}
}

func TestRegister_410ReturnsErrLighthouseGone(t *testing.T) {
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"lighthouse has been deleted"}`, http.StatusGone)
	})

	c := NewClient(srv.URL, "lh_test", "")
	_, err := c.Register(context.Background(), RegisterRequest{AgentVersion: "0.1.0", AgentHostname: "h"})
	if !errors.Is(err, ErrLighthouseGone) {
		t.Errorf("expected ErrLighthouseGone, got %v", err)
	}
}

func TestRegister_401ReturnsErrLighthouseGone(t *testing.T) {
	// Lighthouse delete cascades the bound api_token via FK, so the next
	// agent call's bearer no longer resolves and the server returns 401
	// (not 410). Treat 401 the same as 410 — the lighthouse is gone, the
	// agent should exit cleanly. See status-harbor 7a18479 for the
	// matching cascade-delete change.
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
	})

	c := NewClient(srv.URL, "wrong", "")
	_, err := c.Register(context.Background(), RegisterRequest{AgentVersion: "0.1.0", AgentHostname: "h"})
	if !errors.Is(err, ErrLighthouseGone) {
		t.Errorf("expected ErrLighthouseGone on 401, got %v", err)
	}
}

func TestRegister_NetworkErrorPropagates(t *testing.T) {
	// Point at a non-listening port — should produce a network error.
	c := NewClient("http://127.0.0.1:1", "lh_test", "")
	_, err := c.Register(context.Background(), RegisterRequest{AgentVersion: "0.1.0", AgentHostname: "h"})
	if err == nil {
		t.Fatal("expected network error")
	}
}

func TestSendEvents_HappyPath(t *testing.T) {
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/lighthouse/v1/events" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var got EventsRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.SyncKind != "initial" {
			t.Errorf("expected SyncKind=initial, got %q", got.SyncKind)
		}
		if len(got.Events) != 2 {
			t.Errorf("len(events) = %d, want 2", len(got.Events))
		}
		// Initial-sync rows must have nil prev_state per Interpretation B.
		for i, ev := range got.Events {
			if ev.PrevState != nil {
				t.Errorf("event[%d].PrevState = %v, want nil for initial sync", i, *ev.PrevState)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(EventsResponse{Received: 2})
	})

	c := NewClient(srv.URL, "lh_test", "")
	resp, err := c.SendEvents(context.Background(), EventsRequest{
		SyncKind: "initial",
		Events: []EventInput{
			{CheckID: "c1", NewState: "up"},
			{CheckID: "c2", NewState: "down"},
		},
	})
	if err != nil {
		t.Fatalf("SendEvents: %v", err)
	}
	if resp.Received != 2 {
		t.Errorf("Received = %d, want 2", resp.Received)
	}
}

func TestSendEvents_410ReturnsErrLighthouseGone(t *testing.T) {
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"deleted"}`, http.StatusGone)
	})

	c := NewClient(srv.URL, "lh_test", "")
	_, err := c.SendEvents(context.Background(), EventsRequest{Events: []EventInput{{CheckID: "x", NewState: "up"}}})
	if !errors.Is(err, ErrLighthouseGone) {
		t.Errorf("expected ErrLighthouseGone, got %v", err)
	}
}

func TestSendEvents_400IsNotErrLighthouseGone(t *testing.T) {
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"cross-tenant check_id"}`, http.StatusBadRequest)
	})
	c := NewClient(srv.URL, "lh_test", "")
	_, err := c.SendEvents(context.Background(), EventsRequest{Events: []EventInput{{CheckID: "x", NewState: "up"}}})
	if err == nil {
		t.Fatal("expected error on 400")
	}
	if errors.Is(err, ErrLighthouseGone) {
		t.Error("400 must NOT map to ErrLighthouseGone")
	}
}

func TestHeartbeat_HappyPath_SendsLatenciesAndEtag(t *testing.T) {
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/lighthouse/v1/heartbeat" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var got HeartbeatRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.ConfigEtag != "abc123" {
			t.Errorf("ConfigEtag = %q", got.ConfigEtag)
		}
		if got.CheckLatencies["c1"].LastObservedLatencyMs != 42 {
			t.Errorf("CheckLatencies[c1] = %+v", got.CheckLatencies["c1"])
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HeartbeatResponse{
			ConfigEtag:              "abc123",
			Paused:                  false,
			FlapProtectionThreshold: 1,
		})
	})

	c := NewClient(srv.URL, "lh_test", "")
	resp, err := c.Heartbeat(context.Background(), HeartbeatRequest{
		AgentVersion: "0.1.0",
		ConfigEtag:   "abc123",
		CheckLatencies: map[string]LatencyEntry{
			"c1": {LastObservedLatencyMs: 42},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ConfigEtag != "abc123" {
		t.Errorf("ConfigEtag = %q", resp.ConfigEtag)
	}
}

func TestHeartbeat_410ReturnsErrLighthouseGone(t *testing.T) {
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"deleted"}`, http.StatusGone)
	})
	c := NewClient(srv.URL, "lh_test", "")
	_, err := c.Heartbeat(context.Background(), HeartbeatRequest{})
	if !errors.Is(err, ErrLighthouseGone) {
		t.Errorf("expected ErrLighthouseGone, got %v", err)
	}
}

func TestShutdown_HappyPathPostsReason(t *testing.T) {
	var got ShutdownRequest
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/lighthouse/v1/shutdown" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusNoContent)
	})

	c := NewClient(srv.URL, "lh_test", "")
	if err := c.Shutdown(context.Background(), ShutdownRequest{Reason: "sigterm"}); err != nil {
		t.Fatal(err)
	}
	if got.Reason != "sigterm" {
		t.Errorf("Reason = %q", got.Reason)
	}
}

func TestShutdown_410ReturnsErrLighthouseGone(t *testing.T) {
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"deleted"}`, http.StatusGone)
	})
	c := NewClient(srv.URL, "lh_test", "")
	err := c.Shutdown(context.Background(), ShutdownRequest{Reason: "sigterm"})
	if !errors.Is(err, ErrLighthouseGone) {
		t.Errorf("expected ErrLighthouseGone, got %v", err)
	}
}
