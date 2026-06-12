// Phase 3 — host-metrics collector (design §3.1).
//
// SCOPE: this file ships the COLLECTOR CONTRACT (curated metric-name allowlist,
// Sample type, Collector interface) and a deliberately stubbed implementation.
// The real cross-platform metric reader (gopsutil + protobuf remote_write +
// snappy) needs three new dependencies and a focused implementation pass — it
// is intentionally left as a TODO so we don't ship half-working metric scraping
// to public Apache-2.0 users.
//
// What's here vs what's not:
//   - Curated allowlist + golden-tested AllowedMetrics() — DONE. Locks the
//     contract so the future implementation can't silently grow the cardinality
//     cap (design §3.1 last paragraph).
//   - Collector interface — DONE. Two impls: noopCollector (zero deps, used by
//     the runner today) and the future gopsutilCollector (TODO).
//   - Sender interface — in transport/host_metrics.go (this file shouldn't
//     know about HTTP).
//
// When you implement the real collector:
//   - github.com/shirou/gopsutil/v4 — cross-platform host metrics (linux/darwin/windows).
//   - Honor the AllowedMetrics() allowlist exactly. Exclude per-process,
//     per-container, per-cgroup series — they're cardinality bombs (§3.1).
//   - Bound mount/interface counts (cap to ~20 each) to handle container-rich hosts.
//   - Update hostmetrics_test.go's golden assertion when you add a metric.
package agent

import (
	"context"
	"sort"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// Collector produces one batch of host metric samples per tick. The Sample
// type lives in transport (it's the wire shape; see transport/host_metrics.go).
// Implementations should be safe to call concurrently — the runner ticks on
// its own goroutine.
type Collector interface {
	Collect() ([]transport.HostSample, error)
}

// ctxCollector is an optional add-on that the runner uses to inject a
// shutdown-aware parent context into a Collector. Implementations that
// do long-running work (kubelet fan-out, slow apiserver calls) should
// satisfy this so a SIGTERM mid-tick aborts the in-flight work rather
// than holding the goroutine until the collector's internal budget
// fires. Plain Collectors (noop, /proc reader) need not implement it.
type ctxCollector interface {
	SetContext(ctx context.Context)
}

// applyContext is the runner's helper for wiring a shutdown context
// into an arbitrary Collector. Type-asserts to ctxCollector and
// no-ops if the underlying impl doesn't care about the context.
// Exported (lowercase, package-internal) so RunHostMetrics and tests
// can both reach it.
func applyContext(c Collector, ctx context.Context) {
	if cc, ok := c.(ctxCollector); ok {
		cc.SetContext(ctx)
	}
}

// AllowedMetrics returns the curated metric-name allowlist baked into the
// agent (design §3.1). Returns a fresh sorted slice so the caller can compare
// it against a golden file in tests.
//
// **Important:** the test in hostmetrics_test.go asserts this list verbatim
// against a golden file. Adding/removing entries here is a deliberate cap
// change — update the golden file in the same commit, and re-run the §4.2
// capacity math (per-host series count moves with this list).
func AllowedMetrics() []string {
	out := make([]string, len(allowedMetrics))
	copy(out, allowedMetrics)
	sort.Strings(out)
	return out
}

// allowedMetrics is the source of truth. Adding here adds to every agent's
// emit set. EXCLUDED on purpose: per-process / per-container / per-cgroup
// series — a single container-rich host can produce thousands of those and
// blow metrics_max_active_series in one boot.
var allowedMetrics = []string{
	// CPU (aggregate + per-core via labels).
	"cpu_busy_percent",
	"cpu_user_percent",
	"cpu_system_percent",
	"cpu_iowait_percent",

	// Memory.
	"mem_used_bytes",
	"mem_used_percent",
	"mem_available_bytes",
	"swap_used_bytes",
	"swap_used_percent",

	// Load average.
	"load1",
	"load5",
	"load15",

	// Per-mount filesystem (label: mount).
	"disk_used_bytes",
	"disk_free_bytes",
	"disk_used_percent",
	"disk_inodes_used_percent",

	// Per-device disk I/O (label: device).
	"disk_read_bytes_total",
	"disk_write_bytes_total",
	"disk_io_time_seconds_total",

	// Per-interface network (label: iface).
	"net_rx_bytes_total",
	"net_tx_bytes_total",
	"net_rx_packets_total",
	"net_tx_packets_total",
	"net_rx_errors_total",
	"net_tx_errors_total",

	// Agent self-monitoring (no labels). lighthouse_agent_uptime_seconds
	// was retired — X-Lighthouse-Process-Uptime carries the same signal
	// per-request and a monotonically growing counter was a bad fit for
	// the rule allowlist.
	"lighthouse_agent_up",
}

// NewNoopCollector returns a Collector that emits zero samples. Used today
// because the gopsutil-backed real collector is a separate work item; the
// runner is wired to call Collector.Collect() either way so the swap is
// one-line when the real implementation lands.
func NewNoopCollector() Collector {
	return noopCollector{}
}

type noopCollector struct{}

func (noopCollector) Collect() ([]transport.HostSample, error) { return nil, nil }

// MultiCollector fans Collect() out across N collectors and
// concatenates the samples. Used by the central Deployment to emit
// the host /proc collector AND the k8sstats cluster-shape collector
// through the single host-metrics ticker. Individual collector
// failures are independent — a failing k8sstats query doesn't drop
// /proc samples and vice versa.
//
// The child slice is unexported so callers can't mutate the set
// post-construction (which would race with Collect on the runner's
// goroutine). Construct via NewMultiCollector.
type MultiCollector struct {
	collectors []Collector
}

// NewMultiCollector compacts nil entries so callers can do
// `NewMultiCollector(linux, k8s)` where either argument may be nil
// (k8sstats returns nil outside a cluster).
func NewMultiCollector(cs ...Collector) Collector {
	out := MultiCollector{}
	for _, c := range cs {
		if c != nil {
			out.collectors = append(out.collectors, c)
		}
	}
	return out
}

// Collect runs each child Collector and concatenates results.
// Returns the first error encountered but always returns the samples
// from successful children — partial data is better than no data
// for a single transient apiserver hiccup.
func (m MultiCollector) Collect() ([]transport.HostSample, error) {
	var (
		out      []transport.HostSample
		firstErr error
	)
	for _, c := range m.collectors {
		samples, err := c.Collect()
		if err != nil && firstErr == nil {
			firstErr = err
		}
		out = append(out, samples...)
	}
	return out, firstErr
}

// SetContext forwards the runner's shutdown-aware context to each
// child collector that opts in via ctxCollector. Lets the runner do a
// single applyContext(multi, ctx) call without knowing which children
// care about cancellation.
func (m MultiCollector) SetContext(ctx context.Context) {
	for _, c := range m.collectors {
		applyContext(c, ctx)
	}
}
