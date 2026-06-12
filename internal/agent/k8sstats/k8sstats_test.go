package k8sstats

import (
	"strings"
	"testing"
)

// nodeSamples / podSamples / pvcSamples are pure helpers — exercising
// them directly pins the metric names + label conventions without
// standing up a fake apiserver. The Collect() integration path (which
// reads the in-cluster client) is covered by the e2e suite.

func TestNodeSamples_CountReadyAndNot(t *testing.T) {
	nodes := []nodeItem{
		// Ready node.
		{Status: nodeStatus{Conditions: []nodeCondition{{Type: "Ready", Status: "True"}}}},
		// NotReady — condition exists but Status != True.
		{Status: nodeStatus{Conditions: []nodeCondition{{Type: "Ready", Status: "False"}}}},
		// No Ready condition at all — treated as not ready.
		{},
	}
	samples := nodeSamples(nodes, 0)

	got := map[string]float64{}
	for _, s := range samples {
		got[s.Name] = s.Value
	}
	if got["k8s_node_count"] != 3 {
		t.Errorf("k8s_node_count = %v; want 3", got["k8s_node_count"])
	}
	if got["k8s_nodes_ready"] != 1 {
		t.Errorf("k8s_nodes_ready = %v; want 1", got["k8s_nodes_ready"])
	}
	if got["k8s_nodes_not_ready"] != 2 {
		t.Errorf("k8s_nodes_not_ready = %v; want 2", got["k8s_nodes_not_ready"])
	}
}

func TestPodSamples_BucketsByNamespaceAndPhase(t *testing.T) {
	pods := []podItem{
		mkPod("prod", "Running", 0, 1),
		mkPod("prod", "Running", 2, 0),
		mkPod("prod", "Pending", 0, 0),
		mkPod("staging", "Failed", 0, 5),
		// Empty namespace — skipped (kube-scheduler artifacts).
		mkPod("", "Running", 0, 0),
	}
	samples := podSamples(pods, 0)

	type key struct {
		name, ns string
	}
	got := map[key]float64{}
	for _, s := range samples {
		got[key{s.Name, s.Labels["namespace"]}] = s.Value
	}

	if got[key{"k8s_pods_running", "prod"}] != 2 {
		t.Errorf("prod running = %v; want 2", got[key{"k8s_pods_running", "prod"}])
	}
	if got[key{"k8s_pods_pending", "prod"}] != 1 {
		t.Errorf("prod pending = %v; want 1", got[key{"k8s_pods_pending", "prod"}])
	}
	if got[key{"k8s_pods_failed", "staging"}] != 1 {
		t.Errorf("staging failed = %v; want 1", got[key{"k8s_pods_failed", "staging"}])
	}
	// prod's restarts: 0 + 2 + 0 = 2 (test pods have restart counts
	// 0, 2, 0 — the trailing arg in mkPod was a dummy and isn't read).
	if got[key{"k8s_pods_restarts_total", "prod"}] != 2 {
		t.Errorf("prod restarts = %v; want 2", got[key{"k8s_pods_restarts_total", "prod"}])
	}
	// Empty-namespace pod must not produce a series under "".
	for _, s := range samples {
		if s.Labels["namespace"] == "" {
			t.Errorf("found sample with empty-namespace label: %+v", s)
		}
	}
}

// Cardinality cap matters because a CI cluster with per-PR namespaces
// would otherwise blow the per-team series budget on the central pod's
// first tick. The cap is alphabetically stable so the same subset
// reports each tick — flapping cardinality is worse than dropping a
// few namespaces.
func TestPodSamples_CapsNamespacesAtMaxLabelValues(t *testing.T) {
	pods := make([]podItem, 0, maxLabelValues+10)
	for i := 0; i < maxLabelValues+10; i++ {
		// Pad names so the sort order is digit-aware (ns-000…ns-074).
		ns := mkNamespaceName(i)
		pods = append(pods, mkPod(ns, "Running", 0, 0))
	}
	samples := podSamples(pods, 0)

	seenNS := map[string]struct{}{}
	for _, s := range samples {
		if ns := s.Labels["namespace"]; ns != "" {
			seenNS[ns] = struct{}{}
		}
	}
	if len(seenNS) > maxLabelValues {
		t.Errorf("seen %d namespaces; cap is %d", len(seenNS), maxLabelValues)
	}
	// Truncated set must be the alphabetically-lowest ones (stable
	// across ticks). ns-000 should be present, ns-(cap+1)+ should not.
	if _, ok := seenNS[mkNamespaceName(0)]; !ok {
		t.Errorf("expected lowest namespace %q to be present", mkNamespaceName(0))
	}
	if _, ok := seenNS[mkNamespaceName(maxLabelValues+5)]; ok {
		t.Errorf("expected namespace %q to be dropped past the cap", mkNamespaceName(maxLabelValues+5))
	}
}

// --- helpers ----------------------------------------------------------

func mkPod(ns, phase string, restarts, _ int) podItem {
	p := podItem{}
	p.Metadata.Namespace = ns
	p.Status.Phase = phase
	if restarts > 0 {
		p.Status.ContainerStatuses = []struct {
			RestartCount int `json:"restartCount"`
		}{{RestartCount: restarts}}
	}
	return p
}

func mkNamespaceName(i int) string {
	// Zero-pad to 3 digits so string sort matches numeric order.
	var b strings.Builder
	b.WriteString("ns-")
	switch {
	case i < 10:
		b.WriteString("00")
	case i < 100:
		b.WriteString("0")
	}
	b.WriteString(itoa(i))
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
