// Package k8sstats is the cluster-shape metrics collector that the
// central Deployment of the Helm chart runs once per cluster (Phase
// 2.4). Emits k8s_* metrics over the host-metrics transport — same
// pipeline as cpu_busy_percent / mem_used_percent etc.
//
// Source of truth: kube-apiserver (node list + conditions + allocatable
// resources, pod list grouped by namespace + phase + restart counts,
// PVC list with status.capacity). The kubelet /stats/summary endpoint
// is the obvious next source for per-node CPU / memory / disk USAGE
// percentages but it's deferred to a follow-up — apiserver-only data
// is enough to surface "nodes not ready", "pods stuck pending", and
// fleet sizes, which are the load-bearing first cuts.
//
// Cardinality: bounded per-cluster, not per-pod. We never label by pod
// name — those series would blow the per-team cap on a busy cluster.
// Labels we DO use: node (per-node metrics), namespace (per-namespace
// pod counts), persistentvolumeclaim (per-PVC fill). Each one is
// capped via maxLabelValues so a runaway namespace can't break a
// neighbour.
//
// Reuses the same shape as discovery/kube.go: minimal HTTPS client
// reading the in-cluster service account token + CA. No client-go
// dependency — keeps the agent binary small and avoids the version
// matrix client-go imposes on consumers.
package k8sstats

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

const (
	tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	caPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	// maxLabelValues caps the per-label cardinality emitted in one
	// tick. Same reasoning as the host collector's maxMounts /
	// maxNetInterfaces: a runaway producer (one namespace per Helm
	// release in a CI cluster) can't blow the per-team series cap.
	maxLabelValues = 64

	// tickBudget is the wall-clock ceiling for one Collect() call.
	// Sized to comfortably absorb the kubelet fan-out on ~80 nodes
	// at 8-way concurrency + 5s per-call timeout (worst case ~50s).
	// On larger clusters the last few nodes drop out of the per-tick
	// result; the cluster aggregate accurately reflects the subset
	// we got, and any per-tick gap is replaced on the next interval.
	//
	// The runner serialises ticks (next emit waits for the current
	// to return) so this also caps how far ticks can fall behind:
	// at most one tick of work in flight at any time.
	tickBudget = 60 * time.Second
)

// Collector implements the agent.Collector contract — Collect returns
// a batch of transport.HostSample. Construct via NewCollector, which
// returns (nil, nil) outside a cluster so the agent runner can do an
// unconditional `c, _ := k8sstats.NewCollector(); if c != nil { ... }`.
type Collector struct {
	client *kubeClient
}

// NewCollector returns the production collector. Returns (nil, nil)
// outside a cluster (KUBERNETES_SERVICE_HOST unset) or when the
// service-account token isn't present — both treated as "this isn't
// a k8s install, skip silently". An error indicates the env DOES
// look like a cluster but something we couldn't recover from went
// wrong (invalid CA bundle, etc.).
func NewCollector() (*Collector, error) {
	cli, err := inClusterClient()
	if err != nil {
		return nil, err
	}
	if cli == nil {
		return nil, nil
	}
	return &Collector{client: cli}, nil
}

// Collect produces one batch of cluster-shape samples. Errors from
// individual apiserver calls are swallowed (logged is the runner's
// job) — a transient apiserver hiccup shouldn't black out the whole
// tick. Failure of one query means missing samples for that section,
// not aborting the rest.
func (c *Collector) Collect() ([]transport.HostSample, error) {
	if c == nil || c.client == nil {
		return nil, nil
	}
	start := time.Now()
	defer func() {
		// Pressure signal: when a Collect runs past 70% of the
		// budget, the kubelet fan-out tail is about to start
		// dropping nodes. We deliberately don't warn at 50% — the
		// default host-metrics interval is 30s (= tickBudget/2) so
		// a half-budget threshold would fire every tick on
		// moderately busy clusters and turn the signal into noise.
		// 70% (~42s) gives 18s of headroom for fleet growth before
		// real data starts dropping and surfaces fleet-scale
		// pressure to operators in time to either raise tickBudget,
		// increase the Console-side metrics interval, or split the
		// cluster across multiple Lighthouses.
		if dur := time.Since(start); dur > tickBudget*7/10 {
			slog.Warn("k8sstats tick approaching budget",
				"duration", dur, "budget", tickBudget)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), tickBudget)
	defer cancel()

	nowMs := time.Now().UnixMilli()
	out := make([]transport.HostSample, 0, 32)

	// Node list first — we need it both for nodeSamples (count /
	// ready / not-ready) and for the kubelet fan-out (names +
	// allocatable). One miss here drops everything downstream.
	nodes, err := c.client.listNodes(ctx)
	if err == nil {
		out = append(out, nodeSamples(nodes, nowMs)...)

		// Per-node usage from kubelet /stats/summary. Run with a
		// generous wall-clock budget so one stuck kubelet can't
		// starve the others — the bounded worker pool + per-call
		// timeout inside k.get() already protect us. We use the
		// outer ctx so the ticker's stop signal still cancels.
		summaries := c.client.fanOutSummaries(ctx, nodes)

		// Build a quick node-name → nodeItem map so usage rendering
		// doesn't re-scan the slice. Tiny — at most a few thousand
		// entries on the largest realistic cluster.
		nodeByName := make(map[string]nodeItem, len(nodes))
		for _, n := range nodes {
			nodeByName[n.Metadata.Name] = n
		}

		for name, s := range summaries {
			out = append(out, nodeUsageSamples(name, nodeByName[name], s, nowMs)...)
		}
		out = append(out, clusterAggregateSamples(nodes, summaries, nowMs)...)
		out = append(out, pvcUsageSamples(summaries, nowMs)...)
	}

	if pods, err := c.client.listPods(ctx); err == nil {
		out = append(out, podSamples(pods, nowMs)...)
	}
	if pvcs, err := c.client.listPVCs(ctx); err == nil {
		out = append(out, pvcSamples(pvcs, nowMs)...)
	}
	return out, nil
}

// clusterAggregateSamples emits the two cluster-wide usage gauges
// derived from per-node sums. Skipped when no summaries came back
// (RBAC denial, every kubelet down) so we don't emit a misleading
// 0% — the metric just disappears from the chart, which the empty-
// state copy explains. Computed as sum(usage) / sum(allocatable)
// across the nodes we DID get data for; missing nodes drop out of
// both numerator and denominator so the percentage is honest about
// the subset, not skewed toward 0.
func clusterAggregateSamples(
	nodes []nodeItem,
	summaries map[string]*statsSummary,
	nowMs int64,
) []transport.HostSample {
	if len(summaries) == 0 {
		return nil
	}
	var (
		cpuUsed, cpuAlloc float64
		memUsed, memAlloc float64
		haveCPU, haveMem  bool
	)
	for _, n := range nodes {
		s, ok := summaries[n.Metadata.Name]
		if !ok || s == nil {
			continue
		}
		if alloc, err := parseCPUQuantity(n.Status.Allocatable.CPU); err == nil && alloc > 0 && s.Node.CPU.UsageNanoCores > 0 {
			cpuUsed += float64(s.Node.CPU.UsageNanoCores) / 1e9
			cpuAlloc += alloc
			haveCPU = true
		}
		if alloc, err := parseMemoryQuantity(n.Status.Allocatable.Memory); err == nil && alloc > 0 && s.Node.Memory.WorkingSetBytes > 0 {
			memUsed += float64(s.Node.Memory.WorkingSetBytes)
			memAlloc += alloc
			haveMem = true
		}
	}
	out := make([]transport.HostSample, 0, 2)
	if haveCPU && cpuAlloc > 0 {
		out = append(out, transport.HostSample{
			Name: "k8s_cluster_cpu_used_percent",
			Value: cpuUsed / cpuAlloc * 100, Timestamp: nowMs,
		})
	}
	if haveMem && memAlloc > 0 {
		out = append(out, transport.HostSample{
			Name: "k8s_cluster_memory_used_percent",
			Value: memUsed / memAlloc * 100, Timestamp: nowMs,
		})
	}
	return out
}

// pvcUsageSamples walks summary.pods[].volume[] and emits one
// k8s_pvc_used_percent per (namespace, pvc) — deduped because a PVC
// mounted by multiple pods (ReadWriteMany) shows up under each pod.
// Same numbers per replica; we keep the first non-zero capacity
// observation.
//
// Bound at maxLabelValues * 2 to absorb the (namespace, name)
// label-pair cardinality. PVCs are a few-per-namespace concept on
// most clusters; the cap is generous on purpose.
func pvcUsageSamples(summaries map[string]*statsSummary, nowMs int64) []transport.HostSample {
	type stats struct {
		used, capacity float64
	}
	seen := map[pvcKey]stats{}
	for _, s := range summaries {
		for _, p := range s.Pods {
			for _, v := range p.Volume {
				if v.PvcRef.Name == "" || v.CapacityBytes == 0 {
					continue
				}
				k := pvcKey{v.PvcRef.Namespace, v.PvcRef.Name}
				if _, ok := seen[k]; ok {
					continue
				}
				seen[k] = stats{
					used:     float64(v.UsedBytes),
					capacity: float64(v.CapacityBytes),
				}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	// Stable iteration order matters: when the PVC count exceeds the
	// cap, which entries survive must be deterministic across ticks
	// or the dropped series would flap in and out and customers
	// would see broken charts. Sort by "<namespace>/<name>" so the
	// truncation always keeps the alphabetically-lowest subset —
	// same invariant as podSamples().
	keys := make([]pvcKey, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sortPVCKeys(keys)
	if len(keys) > maxLabelValues*2 {
		keys = keys[:maxLabelValues*2]
	}
	out := make([]transport.HostSample, 0, len(keys))
	for _, k := range keys {
		s := seen[k]
		out = append(out, transport.HostSample{
			Name: "k8s_pvc_used_percent",
			Labels: map[string]string{
				"namespace":             k.namespace,
				"persistentvolumeclaim": k.name,
			},
			Value:     s.used / s.capacity * 100,
			Timestamp: nowMs,
		})
	}
	return out
}

// pvcKey is one (namespace, persistentvolumeclaim) tuple — promoted
// to a named type at file scope so the sort helper can take it as a
// parameter (Go can't reference a function-local type from another
// function).
type pvcKey struct {
	namespace, name string
}

// sortPVCKeys orders (namespace, name) tuples lexicographically. Used
// by pvcUsageSamples to give cardinality truncation a stable, tick-
// independent membership rather than letting Go's randomised map
// iteration produce flapping series.
func sortPVCKeys(keys []pvcKey) {
	sort.Slice(keys, func(i, j int) bool {
		return pvcKeyLess(keys[i], keys[j])
	})
}

func pvcKeyLess(a, b pvcKey) bool {
	if a.namespace != b.namespace {
		return a.namespace < b.namespace
	}
	return a.name < b.name
}

// ---- apiserver client (minimal, no client-go) -------------------------

type kubeClient struct {
	apiServer string
	token     string
	httpc     *http.Client
}

func inClusterClient() (*kubeClient, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, nil
	}
	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, nil
	}
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, errors.New("invalid kube CA bundle")
	}
	return &kubeClient{
		apiServer: fmt.Sprintf("https://%s:%s", host, port),
		token:     strings.TrimSpace(string(tokenBytes)),
		httpc: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool},
			},
		},
	}, nil
}

func (k *kubeClient) get(ctx context.Context, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.apiServer+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")
	resp, err := k.httpc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s: %s — %s", path, resp.Status, string(body))
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

// ---- node list --------------------------------------------------------

type nodeList struct {
	Items []nodeItem `json:"items"`
}

type nodeItem struct {
	Metadata nodeMetadata `json:"metadata"`
	Status   nodeStatus   `json:"status"`
}

type nodeMetadata struct {
	Name string `json:"name"`
}

type nodeStatus struct {
	Conditions []nodeCondition `json:"conditions"`
	// Allocatable is post-reservation: what's actually available
	// for scheduling, vs. status.capacity which is the raw
	// hardware. Used as the divisor for the per-node
	// k8s_node_{cpu,memory}_used_percent gauges so the percent
	// matches what kube-scheduler reasons about.
	Allocatable nodeAllocatable `json:"allocatable"`
}

type nodeCondition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

type nodeAllocatable struct {
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
}

func (k *kubeClient) listNodes(ctx context.Context) ([]nodeItem, error) {
	var out nodeList
	if err := k.get(ctx, "/api/v1/nodes", &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

func nodeSamples(nodes []nodeItem, nowMs int64) []transport.HostSample {
	out := make([]transport.HostSample, 0, 3+len(nodes)*1)
	ready := 0
	for _, n := range nodes {
		if isNodeReady(n) {
			ready++
		}
	}
	notReady := len(nodes) - ready
	out = append(out,
		transport.HostSample{Name: "k8s_node_count", Value: float64(len(nodes)), Timestamp: nowMs},
		transport.HostSample{Name: "k8s_nodes_ready", Value: float64(ready), Timestamp: nowMs},
		transport.HostSample{Name: "k8s_nodes_not_ready", Value: float64(notReady), Timestamp: nowMs},
	)
	return out
}

func isNodeReady(n nodeItem) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == "Ready" {
			return c.Status == "True"
		}
	}
	return false
}

// ---- pod list ---------------------------------------------------------

type podList struct {
	Items []podItem `json:"items"`
}

type podItem struct {
	Metadata struct {
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Status struct {
		Phase             string `json:"phase"`
		ContainerStatuses []struct {
			RestartCount int `json:"restartCount"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

func (k *kubeClient) listPods(ctx context.Context) ([]podItem, error) {
	var out podList
	if err := k.get(ctx, "/api/v1/pods", &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// podSamples produces per-namespace counts of Running / Pending /
// Failed pods plus a per-namespace cumulative restart counter. The
// Console wraps the restart counter in rate() to produce a per-second
// "container restart" rate — useful for detecting flapping pods.
//
// Caps namespaces at maxLabelValues so a CI cluster with per-PR
// namespaces can't blow cardinality. Above the cap, namespaces are
// dropped in stable (alphabetical) order so the same set is reported
// each tick — flapping cardinality is worse than under-reporting
// some namespaces.
func podSamples(pods []podItem, nowMs int64) []transport.HostSample {
	type counts struct {
		running, pending, failed int
		restarts                 int
	}
	byNS := map[string]*counts{}
	for _, p := range pods {
		ns := p.Metadata.Namespace
		if ns == "" {
			continue
		}
		c, ok := byNS[ns]
		if !ok {
			c = &counts{}
			byNS[ns] = c
		}
		switch p.Status.Phase {
		case "Running":
			c.running++
		case "Pending":
			c.pending++
		case "Failed":
			c.failed++
		}
		for _, cs := range p.Status.ContainerStatuses {
			c.restarts += cs.RestartCount
		}
	}
	keys := sortedKeys(byNS)
	if len(keys) > maxLabelValues {
		keys = keys[:maxLabelValues]
	}
	out := make([]transport.HostSample, 0, len(keys)*4)
	for _, ns := range keys {
		labels := map[string]string{"namespace": ns}
		c := byNS[ns]
		out = append(out,
			transport.HostSample{Name: "k8s_pods_running", Labels: labels, Value: float64(c.running), Timestamp: nowMs},
			transport.HostSample{Name: "k8s_pods_pending", Labels: labels, Value: float64(c.pending), Timestamp: nowMs},
			transport.HostSample{Name: "k8s_pods_failed", Labels: labels, Value: float64(c.failed), Timestamp: nowMs},
			transport.HostSample{Name: "k8s_pods_restarts_total", Labels: labels, Value: float64(c.restarts), Timestamp: nowMs},
		)
	}
	return out
}

// ---- PVC list ---------------------------------------------------------

type pvcList struct {
	Items []pvcItem `json:"items"`
}

type pvcItem struct {
	Metadata struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"metadata"`
}

func (k *kubeClient) listPVCs(ctx context.Context) ([]pvcItem, error) {
	var out pvcList
	if err := k.get(ctx, "/api/v1/persistentvolumeclaims", &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// pvcSamples emits just the count today. k8s_pvc_used_percent needs
// kubelet /stats/summary (per-node, then proxied through apiserver as
// /api/v1/nodes/{name}/proxy/stats/summary) — that integration is
// deferred to a follow-up so the central pod isn't responsible for
// fanning out N kubelet calls per tick. The count alone is useful for
// fleet sizing and "PVC growth" alerts.
func pvcSamples(pvcs []pvcItem, nowMs int64) []transport.HostSample {
	return []transport.HostSample{
		{Name: "k8s_pvc_count", Value: float64(len(pvcs)), Timestamp: nowMs},
	}
}

// ---- helpers ----------------------------------------------------------

// sortedKeys returns map keys in stable order. Used by podSamples so
// the namespace truncation under the maxLabelValues cap is
// deterministic — same namespaces reported each tick regardless of
// Go's map iteration order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Cheap stable sort — len rarely exceeds 100 namespaces.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
