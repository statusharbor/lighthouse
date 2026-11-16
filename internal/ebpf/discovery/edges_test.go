package discovery

import (
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func TestSourceIdentity(t *testing.T) {
	for want, l := range map[string]Listener{
		"k8s:prod/api":            {Pod: "api-7d9c6b5f4b-x2k8q", Namespace: "prod", ContainerID: "c"},
		"unit:app.service":        {Unit: "app.service", Exe: "/opt/app"},
		"container:/usr/bin/curl": {ContainerID: "c", Exe: "/usr/bin/curl"},
		"exe:/opt/app":            {Exe: "/opt/app"},
		"comm:sh":                 {Comm: "sh"},
	} {
		if got := sourceIdentity(l); got != want {
			t.Errorf("sourceIdentity(%+v) = %q, want %q", l, got, want)
		}
	}
}

func TestInfraDestination(t *testing.T) {
	// DSC-U-F9.
	if !infraDestination(netip.MustParseAddr("10.0.0.2"), 53) || !infraDestination(netip.MustParseAddr("10.0.0.3"), 123) ||
		!infraDestination(netip.MustParseAddr("169.254.169.254"), 80) {
		t.Error("DNS, NTP and metadata must be infrastructure")
	}
	if infraDestination(netip.MustParseAddr("10.0.0.5"), 5432) {
		t.Error("postgres is not infrastructure")
	}
}

func edgeGauges(t *edgeTotals, now time.Time) map[string]float64 {
	out := map[string]float64{}
	t.emit(now, func(name string, v float64, l map[string]string) {
		out[name+"|"+l["src"]+"|"+l["dst"]+"|"+l["dst_port"]] = v
	})
	return out
}

func TestEdgeTotals(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	tot := newEdgeTotals()
	pg := edge{Src: "exe:/opt/app", Dst: "10.0.0.5", Port: 5432}
	// DSC-U-P5: the kernel already folds source ports; repeated drains add up.
	tot.add(pg, 600, now)
	tot.add(pg, 400, now.Add(10*time.Second))
	if got := edgeGauges(tot, now)["lighthouse_ebpf_flow_connections_total|exe:/opt/app|10.0.0.5|5432"]; got != 1000 {
		t.Errorf("edge count = %v, want 1000", got)
	}

	// DSC-U-F10: 600 destinations against a cap of 500.
	tot = newEdgeTotals()
	tot.maxEdges = 500
	for i := range 600 {
		tot.add(edge{Src: "exe:/opt/scan", Dst: "10.1.0." + strconv.Itoa(i%250), Port: uint16(1000 + i)}, 1, now)
	}
	g := edgeGauges(tot, now)
	edges := 0
	for k := range g {
		if len(k) > 0 && k[:len("lighthouse_ebpf_flow_connections_total|exe")] == "lighthouse_ebpf_flow_connections_total|exe" {
			edges++
		}
	}
	if edges != 500 || g["lighthouse_ebpf_flow_connections_total|other|other|0"] != 100 || g["lighthouse_ebpf_flow_edges_truncated_total|||"] != 100 {
		t.Errorf("cap: %d edges, other %v, truncated %v", edges, g["lighthouse_ebpf_flow_connections_total|other|other|0"], g["lighthouse_ebpf_flow_edges_truncated_total|||"])
	}

	// Idle edges are dropped after an hour.
	if _, ok := edgeGauges(tot, now.Add(61*time.Minute))["lighthouse_ebpf_flow_connections_total|exe:/opt/scan|10.1.0.0|1000"]; ok {
		t.Error("idle edge still emitted")
	}
}
