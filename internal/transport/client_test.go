package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

	c := NewClient(srv.URL, "lh_test")
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

	c := NewClient(srv.URL, "lh_test")
	_, err := c.Register(context.Background(), RegisterRequest{AgentVersion: "0.1.0", AgentHostname: "h"})
	if !errors.Is(err, ErrLighthouseGone) {
		t.Errorf("expected ErrLighthouseGone, got %v", err)
	}
}

func TestRegister_AuthFailureReturnsError(t *testing.T) {
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
	})

	c := NewClient(srv.URL, "wrong")
	_, err := c.Register(context.Background(), RegisterRequest{AgentVersion: "0.1.0", AgentHostname: "h"})
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if errors.Is(err, ErrLighthouseGone) {
		t.Errorf("401 must NOT be ErrLighthouseGone; agent would silently exit instead of surfacing the auth issue")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention HTTP 401: %v", err)
	}
}

func TestRegister_NetworkErrorPropagates(t *testing.T) {
	// Point at a non-listening port — should produce a network error.
	c := NewClient("http://127.0.0.1:1", "lh_test")
	_, err := c.Register(context.Background(), RegisterRequest{AgentVersion: "0.1.0", AgentHostname: "h"})
	if err == nil {
		t.Fatal("expected network error")
	}
}
