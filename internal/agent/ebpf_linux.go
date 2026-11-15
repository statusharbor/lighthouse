//go:build linux

package agent

import (
	"cmp"
	"context"
	"net/url"
	"log/slog"
	"time"

	"github.com/cilium/ebpf/rlimit"

	"github.com/statusharbor/lighthouse/internal/ebpf"
	"github.com/statusharbor/lighthouse/internal/agent/k8sstats"
	"github.com/statusharbor/lighthouse/internal/ebpf/discovery"
	"github.com/statusharbor/lighthouse/internal/ebpf/hello"
	"github.com/statusharbor/lighthouse/internal/ebpf/identity"
	"github.com/statusharbor/lighthouse/internal/ebpf/incident"
	"github.com/statusharbor/lighthouse/internal/ebpf/network"
	"github.com/statusharbor/lighthouse/internal/ebpf/procusage"
	"github.com/statusharbor/lighthouse/internal/ebpf/requests"
	"github.com/statusharbor/lighthouse/internal/traces"
	"github.com/statusharbor/lighthouse/internal/transport"
	"github.com/statusharbor/lighthouse/internal/usage"
)

// EBPF event queue bounds: 4 MiB of events in memory during an outage,
// batches of 200, flushed at least every 10 seconds.
const (
	ebpfQueueBytes    = 4 << 20
	ebpfBatchSize     = 200
	ebpfFlushInterval = 10 * time.Second
)

// NewEBPF builds the eBPF manager, the sink its collectors write to
// (also a host-metrics Collector for their gauges) and the event batcher,
// which the caller runs. Collectors start only once the Console's remote
// flags enable them. Returns nils when this agent must not run eBPF: the
// central pod on Kubernetes never loads programs; the per-node DaemonSet
// does.
func NewEBPF(ctx context.Context, cfg *Config, kubernetes bool, send func(context.Context, []transport.EBPFEnvelope) error, hostID string, checks func() []CheckDefinition, tracesPipeline *traces.Pipeline) (*ebpf.Manager, Collector, *ebpf.Batcher) {
	if kubernetes && !cfg.Agent.IsHostMetricsOnly() {
		return nil, nil, nil
	}
	killed := cfg.Agent.EBPF == "off"
	if !killed {
		// Kernels before 5.11 charge BPF memory against RLIMIT_MEMLOCK.
		if err := rlimit.RemoveMemlock(); err != nil {
			slog.Warn("ebpf: remove memlock limit failed; loading may fail on old kernels", "error", err)
		}
	}
	batcher := ebpf.NewBatcher(send, ebpfQueueBytes, ebpfBatchSize, ebpfFlushInterval)
	sink := newEBPFSink(hostID, ebpf.BootID(), batcher)
	host := ebpf.ProbeHost()
	podList, err := k8sstats.NodePodLister(hostID)
	if err != nil {
		slog.Warn("ebpf: pod lookup unavailable; processes resolve to containers only", "error", err)
	}
	pods := identity.NewPodResolver(podList, 30*time.Second)
	ident := identity.New(cfg.Agent.ProcRoot, pods)
	// Per-process attribution (plan 05): the poller needs no eBPF and runs
	// even with the kill switch on; the eBPF collectors feed it.
	acct := usage.NewAccountant()
	poller := usage.NewPoller(acct, cfg.Agent.ProcRoot, func(ctx context.Context, uid string) (string, string, bool) {
		p, ok := pods.Resolve(ctx, uid)
		return p.Namespace, p.Name, ok
	})
	netC := network.New(ident, cfg.Agent.ProcRoot)
	netC.Usage, netC.GroupOf = acct, poller.GroupOf
	m := ebpf.NewManager(ctx, []ebpf.Collector{
		hello.New(), ident, incident.New(ident.Cache), discovery.New(ident, cfg.Agent.ProcRoot),
		netC, procusage.New(ident, acct, poller),
		requestsCollector(ident, cfg, checks, tracesPipeline),
	}, host, killed, sink.forCollector)
	slog.Info("ebpf manager ready", "kill_switch", killed, "kernel", host.KernelRelease, "btf", host.BTF, "lockdown", host.Lockdown)
	return m, NewMultiCollector(sink, poller), batcher
}

// requestsCollector builds the passive request metrics collector; the
// agent's own HTTP checks are excluded from real traffic (L7-U-F4).
func requestsCollector(ident *identity.Collector, cfg *Config, checks func() []CheckDefinition, p *traces.Pipeline) *requests.Collector {
	c := requests.New(ident, cfg.Agent.OBI.Path, cfg.Agent.OBI.MetricsURL, cfg.Agent.OBI.Ports)
	// OBI traces (status-harbor docs/eBPF/11-traces.md): the collector
	// owns the loopback receiver; a supervised OBI gets a token per start,
	// a sidecar shares only the pod's loopback.
	if p != nil {
		c.Traces = p
		p.Resolve = c.TraceIdentity
		if cfg.Agent.OBI.Path != "" {
			p.Token = traces.NewToken()
		}
	}
	c.Checks = func() []requests.CheckTarget {
		var out []requests.CheckTarget
		for _, d := range checks() {
			if t, ok := checkTarget(d.URL); ok {
				out = append(out, t)
			}
		}
		return out
	}
	return c
}

func checkTarget(raw string) (requests.CheckTarget, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return requests.CheckTarget{}, false
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return requests.CheckTarget{Port: port, Path: cmp.Or(u.Path, "/")}, true
}
