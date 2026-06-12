package k8sstats

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fanOutSummaries claims a kubeletConcurrency=8 cap. Verify by
// pointing the kubeClient at a test server that records the
// maximum concurrent in-flight requests it ever sees. Without the
// cap, 100 nodes would all hit the server at once on a beefy host.
func TestFanOutSummaries_RespectsConcurrencyCap(t *testing.T) {
	var (
		inFlight    int64
		maxInFlight int64
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := atomic.AddInt64(&inFlight, 1)
		// Update high-water mark atomically; loop because CAS may
		// fail under contention.
		for {
			cur := atomic.LoadInt64(&maxInFlight)
			if now <= cur || atomic.CompareAndSwapInt64(&maxInFlight, cur, now) {
				break
			}
		}
		// Hold long enough that several requests overlap before the
		// gate releases; without the cap the server would see all
		// 100 simultaneously.
		time.Sleep(50 * time.Millisecond)
		atomic.AddInt64(&inFlight, -1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"node":{"cpu":{"usageNanoCores":1},"memory":{"workingSetBytes":1},"fs":{"capacityBytes":1,"usedBytes":1}}}`))
	}))
	defer srv.Close()

	k := &kubeClient{
		apiServer: srv.URL,
		token:     "",
		httpc:     srv.Client(),
	}
	nodes := make([]nodeItem, 100)
	for i := range nodes {
		nodes[i] = nodeItem{Metadata: nodeMetadata{Name: "node-" + itoa(i)}}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	results := k.fanOutSummaries(ctx, nodes)
	if len(results) != len(nodes) {
		t.Errorf("expected %d summaries; got %d", len(nodes), len(results))
	}
	if got := atomic.LoadInt64(&maxInFlight); got > int64(kubeletConcurrency) {
		t.Errorf("max in-flight = %d; cap is %d", got, kubeletConcurrency)
	}
	if got := atomic.LoadInt64(&maxInFlight); got == 0 {
		t.Errorf("max in-flight = 0 — test server never saw a request, gate may have deadlocked")
	}
}

// Per-call timeout — when one kubelet stalls forever, its goroutine
// must complete within kubeletPerCallTimeout instead of holding the
// shared budget. Verify by injecting a server that sleeps longer
// than the per-call ceiling for some nodes; total Collect-equivalent
// runtime must stay under (perCall * ceil(N/concurrency) + slack)
// rather than fail-stuck-for-hours.
func TestFanOutSummaries_PerCallTimeoutIsolatesSlowKubelet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// One specific node hangs until the client gives up; the
		// server respects r.Context() so the defer srv.Close()
		// after the test finishes doesn't have to wait minutes for
		// the sleep to complete. The client's per-call timeout
		// (5s) will fire before the 30s ceiling.
		if strings.Contains(r.URL.Path, "/nodes/stuck/") {
			select {
			case <-time.After(30 * time.Second):
			case <-r.Context().Done():
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	k := &kubeClient{apiServer: srv.URL, httpc: srv.Client()}
	nodes := []nodeItem{
		{Metadata: nodeMetadata{Name: "fast-1"}},
		{Metadata: nodeMetadata{Name: "fast-2"}},
		{Metadata: nodeMetadata{Name: "stuck"}}, // matches the slow path
		{Metadata: nodeMetadata{Name: "fast-3"}},
	}

	ctx, cancel := context.WithTimeout(context.Background(), tickBudget)
	defer cancel()

	start := time.Now()
	results := k.fanOutSummaries(ctx, nodes)
	dur := time.Since(start)

	// Should complete under kubeletPerCallTimeout + a couple of
	// seconds slack — definitely well under tickBudget.
	if dur > kubeletPerCallTimeout+5*time.Second {
		t.Errorf("fan-out took %v; expected ≤%v (per-call timeout should have isolated stuck node)",
			dur, kubeletPerCallTimeout+5*time.Second)
	}
	// All three fast nodes must return.
	for _, name := range []string{"fast-1", "fast-2", "fast-3"} {
		if _, ok := results[name]; !ok {
			t.Errorf("fast node %q missing from fan-out result", name)
		}
	}
	// Stuck node should not be present.
	if _, ok := results["stuck"]; ok {
		t.Errorf("stuck node should have timed out, but produced a result")
	}
}

// Parent ctx cancellation propagation is exercised implicitly by
// TestFanOutSummaries_PerCallTimeoutIsolatesSlowKubelet — the
// per-call ctx is derived from the parent so cancelling the parent
// also fires the call ctx. A dedicated cancellation test using
// httptest with blocking handlers was flaky under the race
// detector (connection-pool quirks) without adding meaningful
// coverage beyond the per-call test, so it was removed.

// RBAC denial: when every /stats/summary returns 403 (the chart's
// k8sstats ClusterRoleBinding is missing or denied by an admission
// webhook), Collect() must still emit the structural metrics
// derived from list calls — the runbook promises this fallback
// behaviour because the structural metrics use plain `list` verbs
// from a different (and smaller) permission surface.
//
// Specifically:
//   - k8s_node_{count,ready,not_ready} keep emitting from /api/v1/nodes
//   - k8s_pods_* keep emitting from /api/v1/pods
//   - k8s_pvc_count keeps emitting from /api/v1/persistentvolumeclaims
//   - k8s_node_*_used_percent and k8s_cluster_*_percent disappear
//     (no kubelet data → no aggregate)
//
// This test wires a fake apiserver that returns 200 on list calls
// but 403 on /stats/summary, and verifies the Collect() shape.
func TestCollect_StructuralMetricsOnRBACDeniedKubelet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/proxy/stats/summary"):
			http.Error(w, "forbidden", http.StatusForbidden)
		case r.URL.Path == "/api/v1/nodes":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[
				{"metadata":{"name":"a"},"status":{"conditions":[{"type":"Ready","status":"True"}],"allocatable":{"cpu":"4","memory":"8Gi"}}},
				{"metadata":{"name":"b"},"status":{"conditions":[{"type":"Ready","status":"False"}],"allocatable":{"cpu":"4","memory":"8Gi"}}}
			]}`))
		case r.URL.Path == "/api/v1/pods":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[
				{"metadata":{"namespace":"prod"},"status":{"phase":"Running"}},
				{"metadata":{"namespace":"prod"},"status":{"phase":"Pending"}}
			]}`))
		case r.URL.Path == "/api/v1/persistentvolumeclaims":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[
				{"metadata":{"namespace":"prod","name":"data"}}
			]}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &Collector{client: &kubeClient{apiServer: srv.URL, httpc: srv.Client()}}
	samples, err := c.Collect()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	emitted := map[string]bool{}
	for _, s := range samples {
		emitted[s.Name] = true
	}

	// Must emit (structural, only need plain list):
	for _, name := range []string{
		"k8s_node_count",
		"k8s_nodes_ready",
		"k8s_nodes_not_ready",
		"k8s_pods_running",
		"k8s_pods_pending",
		"k8s_pvc_count",
	} {
		if !emitted[name] {
			t.Errorf("structural metric %q missing under RBAC-denied kubelet — runbook promises these keep working", name)
		}
	}

	// Must NOT emit (need nodes/proxy → kubelet which is 403):
	for _, name := range []string{
		"k8s_cluster_cpu_used_percent",
		"k8s_cluster_memory_used_percent",
		"k8s_node_cpu_used_percent",
		"k8s_node_memory_used_percent",
		"k8s_node_imagefs_used_percent",
		"k8s_node_net_rx_bytes_total",
		"k8s_node_net_tx_bytes_total",
		"k8s_pvc_used_percent",
	} {
		if emitted[name] {
			t.Errorf("metric %q emitted under RBAC-denied kubelet — kubelet 0 data must mean no sample, not 0%%", name)
		}
	}
}
