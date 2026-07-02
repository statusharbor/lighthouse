package database

import (
	"context"
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

type stubSender struct{}

func (stubSender) SendDatabaseSnapshots(context.Context, transport.DBSnapshotRequest) error {
	return nil
}

func gateWithLease(ttl int) *transport.DatabaseGate {
	return &transport.DatabaseGate{
		Enabled: true,
		Clusters: []transport.DatabaseGateCluster{{
			DatabaseID:              "db1",
			Engine:                  "postgres",
			SlowQueryLiveTTLSeconds: ttl,
			Nodes:                   []transport.DatabaseGateNode{{NodeID: "n1", DSN: "postgres://x"}},
		}},
	}
}

// TestSlowExpiryFrom pins the TTL->deadline conversion: a positive TTL yields
// now()+ttl, a zero/negative TTL yields the zero time (no lease).
func TestSlowExpiryFrom(t *testing.T) {
	before := time.Now()
	got := slowExpiryFrom(60)
	if got.Before(before.Add(59*time.Second)) || got.After(time.Now().Add(61*time.Second)) {
		t.Fatalf("slowExpiryFrom(60) = %v, want ~now+60s", got)
	}
	if z := slowExpiryFrom(0); !z.IsZero() {
		t.Fatalf("slowExpiryFrom(0) = %v, want zero time", z)
	}
	if z := slowExpiryFrom(-5); !z.IsZero() {
		t.Fatalf("slowExpiryFrom(-5) = %v, want zero time", z)
	}
}

// TestApplyGate_SlowLeaseResetsOnlyOnFreshGate is the core #24 rule: a fresh
// (re-fetched) gate resets the self-expiry deadline; a cached re-apply must
// NOT, otherwise the lease would be pushed forward every heartbeat and never
// expire. It also checks that a fresh ttl=0 gate stops the lease.
func TestApplyGate_SlowLeaseResetsOnlyOnFreshGate(t *testing.T) {
	c := NewController(stubSender{}, "v-test", nil)
	// Pre-seed a running cluster so ApplyGate takes the update branch and does
	// not spawn a real collection goroutine (which would try to dial a DB).
	rr := &clusterRunner{cancel: func() {}}
	c.running["db1"] = rr

	// Fresh gate carrying a 60s lease: lease opens.
	c.ApplyGate(gateWithLease(60), true)
	if !rr.slowLeaseActive(time.Now()) {
		t.Fatal("fresh 60s lease should be active")
	}
	first := rr.slowExpiry.Load()

	// Cached re-apply (fresh=false) with the same gate: deadline must not move.
	c.ApplyGate(gateWithLease(60), false)
	if got := rr.slowExpiry.Load(); got != first {
		t.Fatal("cached re-apply reset the lease deadline; it must be left running")
	}

	// Fresh gate with a longer lease (extend): deadline moves out.
	c.ApplyGate(gateWithLease(600), true)
	if ext := rr.slowExpiry.Load(); ext == first || !ext.After(*first) {
		t.Fatalf("fresh extend did not push the deadline out: %v -> %v", first, ext)
	}

	// Fresh gate with ttl=0 (manual stop): lease closes.
	c.ApplyGate(gateWithLease(0), true)
	if rr.slowLeaseActive(time.Now()) {
		t.Fatal("fresh ttl=0 gate should stop the lease")
	}
}

// TestSlowLeaseActive_ExpiredDeadline confirms a deadline in the past reads as
// inactive - the self-expiry the console relies on (a natural expiry writes no
// new gate, so the agent must stop itself).
func TestSlowLeaseActive_ExpiredDeadline(t *testing.T) {
	rr := &clusterRunner{cancel: func() {}}
	rr.setSlowExpiry(time.Now().Add(-time.Second))
	if rr.slowLeaseActive(time.Now()) {
		t.Fatal("a past deadline must read as inactive")
	}
	// Unset (zero) deadline is also inactive.
	rr.setSlowExpiry(time.Time{})
	if rr.slowLeaseActive(time.Now()) {
		t.Fatal("zero deadline must read as inactive")
	}
}
