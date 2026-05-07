package transport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// roundTrip decodes the fixture into v, marshals back, then asserts
// every top-level key in the original fixture survives. Mirrors the
// server-side test in status-harbor/internal/api/wire_test.go so a
// rename or removal on either side fails CI in that side's repo.
//
// We don't assert key-set equality so additive changes (new fields
// with omitempty) don't trip the test.
func roundTrip(t *testing.T, fixture string, v any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "v1", fixture))
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixture, err)
	}

	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("%s: unmarshal into %T failed: %v", fixture, v, err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("%s: re-marshal failed: %v", fixture, err)
	}

	var fixtureMap, outMap map[string]any
	_ = json.Unmarshal(raw, &fixtureMap)
	_ = json.Unmarshal(out, &outMap)
	for k := range fixtureMap {
		if _, ok := outMap[k]; !ok {
			t.Errorf("%s: top-level key %q lost on round-trip — likely a rename or removed field on the agent type %T", fixture, k, v)
		}
	}
}

// ---------------------------------------------------------------------------
// /register
// ---------------------------------------------------------------------------

func TestWire_RegisterRequest(t *testing.T) {
	roundTrip(t, "register_request.json", &RegisterRequest{})
}

func TestWire_RegisterResponse(t *testing.T) {
	roundTrip(t, "register_response.json", &RegisterResponse{})
}

// ---------------------------------------------------------------------------
// /heartbeat
// ---------------------------------------------------------------------------

func TestWire_HeartbeatRequest(t *testing.T) {
	roundTrip(t, "heartbeat_request.json", &HeartbeatRequest{})
}

func TestWire_HeartbeatResponse(t *testing.T) {
	roundTrip(t, "heartbeat_response.json", &HeartbeatResponse{})
}

// ---------------------------------------------------------------------------
// /events
// ---------------------------------------------------------------------------

func TestWire_EventsRequest(t *testing.T) {
	roundTrip(t, "events_request.json", &EventsRequest{})
}

func TestWire_EventsResponse(t *testing.T) {
	roundTrip(t, "events_response.json", &EventsResponse{})
}

// ---------------------------------------------------------------------------
// /shutdown
// ---------------------------------------------------------------------------

func TestWire_ShutdownRequest(t *testing.T) {
	roundTrip(t, "shutdown_request.json", &ShutdownRequest{})
}

// ---------------------------------------------------------------------------
// /discoveries
// ---------------------------------------------------------------------------

func TestWire_DiscoveriesRequest(t *testing.T) {
	roundTrip(t, "discoveries_request.json", &DiscoverySnapshotRequest{})
}

func TestWire_DiscoveriesResponse(t *testing.T) {
	roundTrip(t, "discoveries_response.json", &DiscoverySnapshotResponse{})
}
