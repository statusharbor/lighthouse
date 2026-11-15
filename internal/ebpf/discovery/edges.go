package discovery

import (
	"net/netip"
	"strconv"
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf"
	"github.com/statusharbor/lighthouse/internal/ebpf/identity"
)

// edge is one dependency edge series: connections from a source service to
// a destination address and port. Never keyed by source port.
type edge struct {
	Src   string // source identity: "k8s:ns/workload", "unit:x.service", "container:/exe", "exe:/exe"
	Dst   string // destination address
	Port  uint16
	Infra bool // DNS, NTP or the cloud metadata address
	Proxy bool // a service-mesh sidecar's own connections
}

// sourceIdentity is the service identity of a connecting process.
func sourceIdentity(l Listener) string {
	return identity.SourceID(identity.Process{
		Exe: l.Exe, ContainerID: l.ContainerID, Unit: l.Unit, Pod: l.Pod, Namespace: l.Namespace,
	}, l.Comm)
}

var metadataAddrs = map[netip.Addr]bool{
	netip.MustParseAddr("169.254.169.254"): true,
	netip.MustParseAddr("fd00:ec2::254"):   true,
}

// Infrastructure destinations are tagged and hidden from the default map
// (DSC-U-F9).
func infraDestination(addr netip.Addr, port uint16) bool {
	return port == 53 || port == 123 || metadataAddrs[addr.Unmap()]
}

// edgeTotals keeps running connection counts per edge. Past the
// destinations quota, new edges are summed into one "other" edge and
// counted as truncated, so totals stay correct (DSC-U-F10). Edges idle for
// an hour are dropped.
type edgeTotals struct {
	maxEdges  int // 0: the destinations quota
	idle      time.Duration
	totals    map[edge]*total
	other     uint64
	truncated uint64
}

func newEdgeTotals() *edgeTotals {
	return &edgeTotals{idle: time.Hour, totals: map[edge]*total{}}
}

func (t *edgeTotals) add(e edge, n uint64, now time.Time) {
	cur := t.totals[e]
	if cur == nil {
		limit := t.maxEdges
		if limit == 0 {
			limit = ebpf.Quota().Destinations
		}
		if len(t.totals) >= limit {
			t.other += n
			t.truncated++
			return
		}
		cur = &total{}
		t.totals[e] = cur
	}
	cur.n += n
	cur.seen = now
}

func (t *edgeTotals) emit(now time.Time, gauge func(name string, value float64, labels map[string]string)) {
	for e, cur := range t.totals {
		if now.Sub(cur.seen) > t.idle {
			delete(t.totals, e)
			continue
		}
		l := map[string]string{"src": e.Src, "dst": e.Dst, "dst_port": strconv.Itoa(int(e.Port))}
		if e.Infra {
			l["infra"] = "true"
		}
		if e.Proxy {
			l["proxy"] = "true"
		}
		gauge("lighthouse_ebpf_flow_connections_total", float64(cur.n), l)
	}
	if t.other > 0 {
		gauge("lighthouse_ebpf_flow_connections_total", float64(t.other), map[string]string{"src": "other", "dst": "other", "dst_port": "0"})
	}
	gauge("lighthouse_ebpf_flow_edges_truncated_total", float64(t.truncated), nil)
}

type total struct {
	n    uint64
	seen time.Time
}
