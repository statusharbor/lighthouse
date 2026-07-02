package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// TestApplyDatabaseGate_EtagGatedFetch asserts the agent fetches the heavy
// cluster+DSN payload from /config only when the (databases-section) etag
// moves, applies the cheap enabled flag every call, resumes from cache on an
// unchanged etag, and narrows the fetch to ?sections=databases (#11).
func TestApplyDatabaseGate_EtagGatedFetch(t *testing.T) {
	var configHits atomic.Int32
	var lastSections atomic.Value // string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/lighthouse/v1/config" {
			configHits.Add(1)
			lastSections.Store(r.URL.Query().Get("sections"))
			_ = json.NewEncoder(w).Encode(transport.ConfigResponse{
				Databases: &transport.DatabaseGate{
					Enabled: true,
					Clusters: []transport.DatabaseGateCluster{{
						DatabaseID: "db1",
						Engine:     "postgres",
						Nodes:      []transport.DatabaseGateNode{{NodeID: "n1", DSN: "postgres://x"}},
					}},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := transport.NewClient(srv.URL, "lh_test", "")
	r := NewRunner(&Config{Token: "lh_test"}, client, &fakeExecutor{}, "", "")

	var applied []*transport.DatabaseGate
	r.SetDatabaseGateHandler(func(g *transport.DatabaseGate, _ bool) { applied = append(applied, g) })

	ctx := context.Background()

	// First enable on etag e1: fetch once, gate carries clusters.
	r.ApplyDatabaseGate(ctx, &transport.DatabaseGate{Enabled: true}, "e1")
	if got := configHits.Load(); got != 1 {
		t.Fatalf("after first enable: config hits = %d, want 1", got)
	}
	// The cold-path fetch must be narrowed to the databases section (#11).
	if got, _ := lastSections.Load().(string); got != "databases" {
		t.Fatalf("config fetch sections = %q, want \"databases\"", got)
	}
	if n := len(applied); n == 0 || !applied[n-1].Enabled || len(applied[n-1].Clusters) != 1 {
		t.Fatalf("first applied gate = %+v, want enabled with 1 cluster", applied[n-1])
	}

	// Same etag: no re-fetch, still applied (from cache).
	r.ApplyDatabaseGate(ctx, &transport.DatabaseGate{Enabled: true}, "e1")
	if got := configHits.Load(); got != 1 {
		t.Fatalf("same-etag heartbeat re-fetched: config hits = %d, want 1", got)
	}

	// Disabled: stop gate applied, no fetch, cache cleared.
	r.ApplyDatabaseGate(ctx, &transport.DatabaseGate{Enabled: false}, "e1")
	if last := applied[len(applied)-1]; last.Enabled {
		t.Fatalf("disabled heartbeat applied enabled gate: %+v", last)
	}
	if got := configHits.Load(); got != 1 {
		t.Fatalf("disabled heartbeat fetched: config hits = %d, want 1", got)
	}

	// Re-enable on a new etag: fetch again.
	r.ApplyDatabaseGate(ctx, &transport.DatabaseGate{Enabled: true}, "e2")
	if got := configHits.Load(); got != 2 {
		t.Fatalf("new-etag enable: config hits = %d, want 2", got)
	}
}

// TestDatabasesEtag_KeysOffSectionNotScalar pins the #11 gating rule: the
// database refetch keys off config_etags["databases"], not the scalar
// config_etag, and falls back to the scalar only when the section map is
// absent. Concretely, a monitor edit (scalar + checks section bump, databases
// section unchanged) must leave the resolved etag stable so no DSN refetch
// fires.
func TestDatabasesEtag_KeysOffSectionNotScalar(t *testing.T) {
	// Monitor edit: scalar moved, databases section held.
	before := &transport.HeartbeatResponse{
		ConfigEtag:  "scalar-1",
		ConfigEtags: map[string]string{"checks": "c1", "databases": "d1"},
	}
	after := &transport.HeartbeatResponse{
		ConfigEtag:  "scalar-2", // bumped by the monitor edit
		ConfigEtags: map[string]string{"checks": "c2", "databases": "d1"},
	}
	if databasesEtag(before) != databasesEtag(after) {
		t.Fatalf("databases etag changed on a checks-only edit: %q -> %q",
			databasesEtag(before), databasesEtag(after))
	}
	if databasesEtag(after) != "d1" {
		t.Fatalf("databases etag = %q, want the section value d1", databasesEtag(after))
	}

	// A real databases change must move the resolved etag.
	dbChanged := &transport.HeartbeatResponse{
		ConfigEtag:  "scalar-3",
		ConfigEtags: map[string]string{"checks": "c2", "databases": "d2"},
	}
	if databasesEtag(after) == databasesEtag(dbChanged) {
		t.Fatal("databases etag did not change when the databases section moved")
	}

	// Older Console (no config_etags): fall back to the scalar config_etag.
	legacy := &transport.HeartbeatResponse{ConfigEtag: "scalar-legacy"}
	if got := databasesEtag(legacy); got != "scalar-legacy" {
		t.Fatalf("legacy fallback etag = %q, want scalar-legacy", got)
	}
}
