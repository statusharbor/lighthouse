package k8sstats

import (
	"math"
	"testing"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// helper: a node with explicit allocatable cores + bytes.
func node(name, cpu, mem string) nodeItem {
	return nodeItem{
		Metadata: nodeMetadata{Name: name},
		Status:   nodeStatus{Allocatable: nodeAllocatable{CPU: cpu, Memory: mem}},
	}
}

// helper: a stats summary with explicit numeric fields. The kubelet
// struct shape is verbose; this keeps tests legible.
func summary(usageNanoCores, workingSetBytes, fsCap, fsUsed, rx, tx uint64) *statsSummary {
	return &statsSummary{
		Node: statsNode{
			CPU:     statsCPU{UsageNanoCores: usageNanoCores},
			Memory:  statsMemory{WorkingSetBytes: workingSetBytes},
			Fs:      statsFs{CapacityBytes: fsCap, UsedBytes: fsUsed},
			Network: statsNetwork{RxBytes: rx, TxBytes: tx},
		},
	}
}

// indexSamples turns a sample slice into a name→value map for
// terser assertions.
func indexSamples(samples []transport.HostSample) map[string]float64 {
	out := map[string]float64{}
	for _, s := range samples {
		out[s.Name] = s.Value
	}
	return out
}

// nodeUsageSamples should emit five samples for a fully-populated
// summary: CPU%, mem%, disk%, plus the two network counters.
func TestNodeUsageSamples_AllFieldsPresent(t *testing.T) {
	n := node("node-1", "4", "8Gi")
	// 1 core in use of 4 → 25%. 1Gi workingSet of 8Gi → 12.5%.
	// 50GB used of 100GB fs → 50%. rx/tx as raw counters.
	s := summary(
		1_000_000_000,    // 1 core in nanocores
		1024*1024*1024,   // 1 GiB
		100_000_000_000,  // 100 GB capacity
		50_000_000_000,   // 50 GB used
		123456,
		654321,
	)
	got := indexSamples(nodeUsageSamples("node-1", n, s, 0))

	wantPct := map[string]float64{
		"k8s_node_cpu_used_percent":    25,
		"k8s_node_memory_used_percent": 12.5,
		"k8s_node_imagefs_used_percent": 50,
	}
	for name, want := range wantPct {
		if math.Abs(got[name]-want) > 0.01 {
			t.Errorf("%s = %v, want %v", name, got[name], want)
		}
	}
	if got["k8s_node_net_rx_bytes_total"] != 123456 {
		t.Errorf("rx counter = %v, want 123456", got["k8s_node_net_rx_bytes_total"])
	}
	if got["k8s_node_net_tx_bytes_total"] != 654321 {
		t.Errorf("tx counter = %v, want 654321", got["k8s_node_net_tx_bytes_total"])
	}
}

// usageNanoCores == 0 is kubelet's "no rate yet" signal (first sample
// after startup, or a brief miss). We must NOT emit a 0% sample —
// that would look like a healthy idle node and could trick rules
// looking for "node above X%" into never firing.
func TestNodeUsageSamples_SkipsZeroUsageNanoCores(t *testing.T) {
	n := node("node-1", "4", "8Gi")
	s := summary(0, 1024*1024*1024, 100, 50, 0, 0)
	got := indexSamples(nodeUsageSamples("node-1", n, s, 0))
	if _, ok := got["k8s_node_cpu_used_percent"]; ok {
		t.Fatalf("k8s_node_cpu_used_percent must be skipped when usageNanoCores=0; got %v", got)
	}
	// Memory% should still be present — separate signal.
	if _, ok := got["k8s_node_memory_used_percent"]; !ok {
		t.Fatalf("k8s_node_memory_used_percent should still emit when mem data is present")
	}
}

// A node with a malformed allocatable.cpu string (apiserver bug,
// experimental scheduler plugin) must drop the percent metric for
// that node but not affect other nodes — clusterAggregateSamples
// also handles this by skipping the node in the sum.
func TestNodeUsageSamples_SkipsBadAllocatable(t *testing.T) {
	n := node("node-1", "garbage", "8Gi")
	s := summary(1_000_000_000, 1024*1024*1024, 100, 50, 0, 0)
	got := indexSamples(nodeUsageSamples("node-1", n, s, 0))
	if _, ok := got["k8s_node_cpu_used_percent"]; ok {
		t.Fatal("k8s_node_cpu_used_percent must be skipped on bad allocatable.cpu")
	}
	// Mem should still emit — different parser.
	if _, ok := got["k8s_node_memory_used_percent"]; !ok {
		t.Fatal("k8s_node_memory_used_percent should still emit when mem allocatable is parseable")
	}
}

func TestClusterAggregateSamples_AveragesAcrossNodes(t *testing.T) {
	nodes := []nodeItem{
		node("a", "4", "8Gi"),
		node("b", "8", "16Gi"),
	}
	summaries := map[string]*statsSummary{
		// a: 1 core / 4 → 25%, 1Gi / 8Gi → 12.5%
		"a": summary(1_000_000_000, 1024*1024*1024, 0, 0, 0, 0),
		// b: 4 cores / 8 → 50%, 8Gi / 16Gi → 50%
		"b": summary(4_000_000_000, 8*1024*1024*1024, 0, 0, 0, 0),
	}
	got := indexSamples(clusterAggregateSamples(nodes, summaries, 0))
	// Cluster cpu: (1+4) / (4+8) cores = 5/12 ≈ 41.667%
	wantCPU := 5.0 / 12.0 * 100
	if math.Abs(got["k8s_cluster_cpu_used_percent"]-wantCPU) > 0.01 {
		t.Errorf("k8s_cluster_cpu_used_percent = %v, want %v", got["k8s_cluster_cpu_used_percent"], wantCPU)
	}
	// Cluster mem: (1+8) / (8+16) GiB = 9/24 = 37.5%
	wantMem := 9.0 / 24.0 * 100
	if math.Abs(got["k8s_cluster_memory_used_percent"]-wantMem) > 0.01 {
		t.Errorf("k8s_cluster_memory_used_percent = %v, want %v", got["k8s_cluster_memory_used_percent"], wantMem)
	}
}

// When every kubelet call failed, summaries is empty — we must NOT
// emit the cluster gauges (would render as 0% which alerting users
// would treat as healthy).
func TestClusterAggregateSamples_EmptyOnNoSummaries(t *testing.T) {
	got := clusterAggregateSamples([]nodeItem{node("a", "4", "8Gi")}, nil, 0)
	if len(got) != 0 {
		t.Fatalf("expected no samples on empty summaries; got %d", len(got))
	}
}

// Cardinality cap: above maxLabelValues*2 PVCs, the truncation must
// be stable — Go map iteration order is randomised, so without the
// alphabetical sort the dropped series would flap between ticks and
// customers would see broken charts. Pin: alphabetically lowest
// (namespace, name) tuples survive; everything beyond the cap drops.
func TestPvcUsageSamples_StableTruncationAboveCap(t *testing.T) {
	summaries := map[string]*statsSummary{"a": {}}
	// One pod with N PVCs where N > maxLabelValues*2.
	pod := statsPod{PodRef: statsPodRef{Name: "pod-1", Namespace: "ns-0"}}
	total := maxLabelValues*2 + 10
	for i := 0; i < total; i++ {
		// Zero-padded so string sort matches numeric order.
		name := pvcName(i)
		pod.Volume = append(pod.Volume, statsVolume{
			Name:          name,
			CapacityBytes: 100,
			UsedBytes:     50,
			PvcRef:        statsPvcRef{Name: name, Namespace: "ns-0"},
		})
	}
	summaries["a"].Pods = []statsPod{pod}

	got := pvcUsageSamples(summaries, 0)
	if len(got) != maxLabelValues*2 {
		t.Fatalf("expected exactly %d samples after cap; got %d", maxLabelValues*2, len(got))
	}
	// First survivor must be pvc-000; last survivor must be the cap-1 index.
	if got[0].Labels["persistentvolumeclaim"] != pvcName(0) {
		t.Errorf("first sample = %q, want %q", got[0].Labels["persistentvolumeclaim"], pvcName(0))
	}
	last := got[len(got)-1].Labels["persistentvolumeclaim"]
	wantLast := pvcName(maxLabelValues*2 - 1)
	if last != wantLast {
		t.Errorf("last sample = %q, want %q", last, wantLast)
	}
}

func pvcName(i int) string {
	// Zero-pad to 3 digits so string sort matches numeric order
	// across the full cap range (up to 138 with maxLabelValues=64).
	switch {
	case i < 10:
		return "pvc-00" + itoa(i)
	case i < 100:
		return "pvc-0" + itoa(i)
	default:
		return "pvc-" + itoa(i)
	}
}

// PVC fill: same PVC mounted by two pods on different nodes should
// produce ONE sample (deduped by namespace + name), not two.
func TestPvcUsageSamples_DedupesAcrossPods(t *testing.T) {
	makeSummary := func(podName, ns, pvc string, used, cap uint64) *statsSummary {
		s := &statsSummary{}
		s.Pods = append(s.Pods, statsPod{
			PodRef: statsPodRef{Name: podName, Namespace: ns},
			Volume: []statsVolume{{
				Name:          "data",
				CapacityBytes: cap,
				UsedBytes:     used,
				PvcRef:        statsPvcRef{Name: pvc, Namespace: ns},
			}},
		})
		return s
	}
	summaries := map[string]*statsSummary{
		"a": makeSummary("pod-1", "prod", "data", 50, 100),
		"b": makeSummary("pod-2", "prod", "data", 50, 100),
	}
	got := pvcUsageSamples(summaries, 0)
	if len(got) != 1 {
		t.Fatalf("expected one deduped PVC sample, got %d", len(got))
	}
	if got[0].Labels["namespace"] != "prod" || got[0].Labels["persistentvolumeclaim"] != "data" {
		t.Errorf("unexpected PVC labels: %+v", got[0].Labels)
	}
	if math.Abs(got[0].Value-50) > 0.01 {
		t.Errorf("PVC used%% = %v, want 50", got[0].Value)
	}
}
