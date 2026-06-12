// kubelet.go — /stats/summary fetch for per-node + per-PVC usage.
//
// Kubernetes doesn't include real-time CPU/mem/disk usage in the
// apiserver's node object — only allocatable / capacity. The kubelet
// running on each node serves a /stats/summary endpoint with the live
// numbers; we reach it through the apiserver proxy
// (/api/v1/nodes/{name}/proxy/stats/summary) so the central pod
// doesn't need direct network reachability to each kubelet or its
// own client certificate.
//
// RBAC: `nodes/proxy: get` on the ServiceAccount. The chart's
// k8sstats ClusterRole grants this; without it the per-node calls
// return 403 and the percent metrics silently disappear (the
// fallback k8s_node_count / k8s_pods_running still work).
//
// Concurrency: bounded fan-out (kubeletConcurrency workers) because
// N apiserver-proxy round trips per tick on a 100-node cluster would
// otherwise serialize into a 100s+ tick. With concurrency=8 and a
// 5s per-call timeout the worst case is ~63s for 100 nodes — still
// borderline; if anyone runs into it we raise the bound. Per-call
// timeout means one stuck kubelet doesn't block its neighbours.

package k8sstats

import (
	"context"
	"sync"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

const (
	// kubeletConcurrency caps the number of /stats/summary requests
	// in flight per tick. Each call hits the apiserver-proxy which
	// then dials the kubelet on its node — the apiserver is the
	// shared bottleneck. 8 keeps us well below the per-namespace
	// API qps defaults (50 burst on most clusters).
	kubeletConcurrency = 8

	// kubeletPerCallTimeout bounds a single /stats/summary fetch.
	// Per-call (not shared across the fan-out) so one slow kubelet
	// can't blow the budget for the other 99. Sized to absorb a
	// brief apiserver proxy hiccup without giving up too quickly on
	// the genuinely slow stragglers — kubelet itself returns
	// /stats/summary in under 100ms in steady state.
	kubeletPerCallTimeout = 5 * time.Second
)

// statsSummary is the slice of kubelet's /stats/summary we actually
// read. The kubelet emits a richer object (containers, pod CPU/mem
// breakdowns, ephemeral-storage stats); we deliberately ignore the
// per-container view because pod-name labels would blow cardinality
// the moment a CI namespace spins.
// Named sub-types so tests can build a summary without
// reproducing the full anonymous struct literal each time.
type statsSummary struct {
	Node statsNode    `json:"node"`
	Pods []statsPod   `json:"pods"`
}

type statsNode struct {
	CPU     statsCPU     `json:"cpu"`
	Memory  statsMemory  `json:"memory"`
	Network statsNetwork `json:"network"`
	Fs      statsFs      `json:"fs"`
}

type statsCPU struct {
	// nanocores. Divide by 1e9 to get cores in use.
	UsageNanoCores uint64 `json:"usageNanoCores"`
}

type statsMemory struct {
	// workingSetBytes is "memory that isn't reclaimable on pressure"
	// — closer to "real memory in use" than usageBytes (which counts
	// cached pages and overstates pressure).
	WorkingSetBytes uint64 `json:"workingSetBytes"`
}

type statsNetwork struct {
	// Node-wide network counters (kubelet sums interfaces).
	RxBytes uint64 `json:"rxBytes"`
	TxBytes uint64 `json:"txBytes"`
}

type statsFs struct {
	// Node's root filesystem (where container images + pod scratch
	// live). Kubelet also exposes imagefs but the distinction is
	// rarely useful for alerting.
	CapacityBytes uint64 `json:"capacityBytes"`
	UsedBytes     uint64 `json:"usedBytes"`
}

type statsPod struct {
	PodRef statsPodRef    `json:"podRef"`
	Volume []statsVolume  `json:"volume"`
}

type statsPodRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type statsVolume struct {
	Name          string         `json:"name"`
	CapacityBytes uint64         `json:"capacityBytes"`
	UsedBytes     uint64         `json:"usedBytes"`
	PvcRef        statsPvcRef    `json:"pvcRef"`
}

type statsPvcRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// getNodeStatsSummary fetches one node's stats. Errors are returned
// to the caller (which collects them into the per-tick error log) so
// a missing /stats/summary doesn't poison the cluster aggregate.
func (k *kubeClient) getNodeStatsSummary(ctx context.Context, nodeName string) (*statsSummary, error) {
	var out statsSummary
	if err := k.get(ctx, "/api/v1/nodes/"+nodeName+"/proxy/stats/summary", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// fanOutSummaries fetches /stats/summary for every node concurrently
// (bounded at kubeletConcurrency). Returns one map keyed by node name.
// Nodes whose call fails are absent from the result — callers must
// tolerate that (computing per-node-set aggregates from the present
// subset is fine; the cluster aggregate would skew if a non-trivial
// fraction of nodes is missing, but the alternative is hiding ALL
// usage metrics on one stuck kubelet which is worse).
func (k *kubeClient) fanOutSummaries(ctx context.Context, nodes []nodeItem) map[string]*statsSummary {
	out := map[string]*statsSummary{}
	if len(nodes) == 0 {
		return out
	}
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		gate = make(chan struct{}, kubeletConcurrency)
	)
	for _, n := range nodes {
		name := n.Metadata.Name
		if name == "" {
			continue
		}
		// Honour the parent ctx while waiting on the gate — if the
		// Collect()-level ctx ends (agent shutdown, tick cancelled)
		// we stop launching new goroutines instead of blocking on
		// the gate.
		select {
		case <-ctx.Done():
			wg.Wait()
			return out
		case gate <- struct{}{}:
		}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			defer func() { <-gate }()
			// Per-call timeout, NOT the shared parent budget. The
			// parent ctx is still honoured (cancellation propagates
			// down via WithTimeout) but one slow kubelet can use up
			// to kubeletPerCallTimeout without starving the others.
			callCtx, cancel := context.WithTimeout(ctx, kubeletPerCallTimeout)
			defer cancel()
			s, err := k.getNodeStatsSummary(callCtx, name)
			if err != nil || s == nil {
				return
			}
			mu.Lock()
			out[name] = s
			mu.Unlock()
		}(name)
	}
	wg.Wait()
	return out
}

// nodeUsageSamples emits per-node usage gauges + cumulative network
// counters. The summary's network counters are cumulative bytes since
// kubelet started; the Console wraps them in rate() server-side so
// they display as throughput.
//
// usageNanoCores has a couple of edge cases — kubelet returns 0 for
// the first sample after startup (no rate to compute against) and
// occasionally drops the field entirely. We treat 0 as "unknown" and
// skip the sample rather than emitting a misleading zero percent.
func nodeUsageSamples(name string, n nodeItem, s *statsSummary, nowMs int64) []transport.HostSample {
	if s == nil {
		return nil
	}
	out := make([]transport.HostSample, 0, 6)
	labels := map[string]string{"node": name}

	// CPU%
	if s.Node.CPU.UsageNanoCores > 0 {
		if alloc, err := parseCPUQuantity(n.Status.Allocatable.CPU); err == nil && alloc > 0 {
			pct := float64(s.Node.CPU.UsageNanoCores) / 1e9 / alloc * 100
			out = append(out, transport.HostSample{
				Name: "k8s_node_cpu_used_percent", Labels: labels, Value: pct, Timestamp: nowMs,
			})
		}
	}
	// Memory%
	if s.Node.Memory.WorkingSetBytes > 0 {
		if alloc, err := parseMemoryQuantity(n.Status.Allocatable.Memory); err == nil && alloc > 0 {
			pct := float64(s.Node.Memory.WorkingSetBytes) / alloc * 100
			out = append(out, transport.HostSample{
				Name: "k8s_node_memory_used_percent", Labels: labels, Value: pct, Timestamp: nowMs,
			})
		}
	}
	// imagefs % — kubelet's view of the filesystem holding container
	// images + pod scratch space. This is NOT the host's root
	// filesystem; that's already exposed via disk_used_percent{
	// mount="/"} from the DaemonSet's /host/proc/mounts walk. The
	// two metrics intentionally have different names so customers
	// don't write alerts on the wrong signal.
	if s.Node.Fs.CapacityBytes > 0 {
		pct := float64(s.Node.Fs.UsedBytes) / float64(s.Node.Fs.CapacityBytes) * 100
		out = append(out, transport.HostSample{
			Name: "k8s_node_imagefs_used_percent", Labels: labels, Value: pct, Timestamp: nowMs,
		})
	}
	// Network counters (raw — Console runs rate()).
	out = append(out,
		transport.HostSample{
			Name: "k8s_node_net_rx_bytes_total", Labels: labels,
			Value: float64(s.Node.Network.RxBytes), Timestamp: nowMs,
		},
		transport.HostSample{
			Name: "k8s_node_net_tx_bytes_total", Labels: labels,
			Value: float64(s.Node.Network.TxBytes), Timestamp: nowMs,
		},
	)
	return out
}
