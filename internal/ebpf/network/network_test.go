package network

import (
	"net/netip"
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf"
)

var t0 = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func gauges(f *flows) map[string]float64 {
	out := map[string]float64{}
	f.emit(t0, func(name string, v float64, l map[string]string) { out[name+"|"+l["dst"]+":"+l["dst_port"]] = v })
	return out
}

var pg = netip.MustParseAddr("10.0.0.5")

func TestFlows(t *testing.T) {
	f := newFlows()
	// NET-U-F1: first sighting of an old socket (owner unknown): baseline only.
	old := sample{SK: 1, BytesAcked: 1 << 30, SegsOut: 1_000_000, Retrans: 5000, SRTTus: 2000, LPort: 40000, DPort: 5432, Dst: pg}
	f.observe(old, t0)
	if g := gauges(f); g["lighthouse_ebpf_flow_bytes_sent_total|10.0.0.5:5432"] != 0 || len(g) != 1 {
		t.Fatalf("first sighting produced data: %v", g)
	}

	// NET-U-P2 and P1: the next pass gives deltas, ratio and RTT in ms.
	next := old
	next.BytesAcked += 50_000
	next.SegsOut += 1000
	next.Retrans += 20
	next.SRTTus = 12_500
	f.observe(next, t0)
	g := gauges(f)
	if g["lighthouse_ebpf_flow_retransmit_ratio|10.0.0.5:5432"] != 0.02 || g["lighthouse_ebpf_flow_rtt_ms|10.0.0.5:5432"] != 12.5 ||
		g["lighthouse_ebpf_flow_bytes_sent_total|10.0.0.5:5432"] != 50_000 {
		t.Fatalf("deltas: %v", g)
	}

	// NET-U-F4: an idle pass reports no RTT. NET-U-F3: 1 retransmit of 3
	// segments reports no ratio.
	idle := next
	idle.SegsOut += 3
	idle.Retrans++
	f.observe(idle, t0)
	g = gauges(f)
	if _, ok := g["lighthouse_ebpf_flow_rtt_ms|10.0.0.5:5432"]; ok {
		t.Errorf("idle socket reported RTT: %v", g)
	}
	if _, ok := g["lighthouse_ebpf_flow_retransmit_ratio|10.0.0.5:5432"]; ok {
		t.Errorf("ratio from 3 segments: %v", g)
	}

	// NET-U-F2: the address reused by a new socket with small counters is
	// a new baseline, not a negative or huge delta.
	reused := sample{SK: 1, BytesAcked: 100, SegsOut: 2, LPort: 40001, DPort: 5432, Dst: pg}
	f.observe(reused, t0)
	if v := gauges(f)["lighthouse_ebpf_flow_bytes_sent_total|10.0.0.5:5432"]; v != 50_000 {
		t.Errorf("reused socket changed the total: %v", v)
	}

	// Criterion 6: a short connection the agent saw open is counted at close.
	short := sample{SK: 2, BytesAcked: 7000, BytesReceived: 300, SegsOut: 9, LPort: 41000, DPort: 5432, Dst: pg, Src: "exe:/opt/app", Closed: true}
	f.observe(short, t0)
	g = map[string]float64{}
	f.emit(t0, func(name string, v float64, l map[string]string) { g[name+"|"+l["src"]] = v })
	if g["lighthouse_ebpf_flow_bytes_sent_total|exe:/opt/app"] != 7000 || g["lighthouse_ebpf_flow_bytes_received_total|exe:/opt/app"] != 300 {
		t.Errorf("short connection: %v", g)
	}
	if _, ok := f.last[2]; ok {
		t.Error("closed socket kept")
	}
}

func TestFlows_Filters(t *testing.T) {
	f := newFlows()
	mapped := netip.MustParseAddr("::ffff:10.0.0.5")
	f.observe(sample{SK: 1, BytesAcked: 10, SegsOut: 1, LPort: 40000, DPort: 5432, Dst: mapped, Src: "exe:/a", Closed: true}, t0)
	f.observe(sample{SK: 2, BytesAcked: 10, SegsOut: 1, LPort: 40001, DPort: 5432, Dst: pg, Src: "exe:/a", Closed: true}, t0)
	f.observe(sample{SK: 3, BytesAcked: 10, LPort: 40002, DPort: 6379, Dst: netip.MustParseAddr("127.0.0.1"), Src: "exe:/a", Closed: true}, t0) // NET-E-F8
	f.observe(sample{SK: 4, BytesAcked: 10, LPort: 5432, DPort: 50123, Dst: pg, Closed: true}, t0)                                              // server side
	g := gauges(f)
	// NET-U-P7: the v4-mapped and plain IPv4 forms are one flow.
	if g["lighthouse_ebpf_flow_bytes_sent_total|10.0.0.5:5432"] != 20 || len(g) != 3 {
		t.Fatalf("filters: %v", g)
	}

	// Sockets the iterator stops listing are forgotten.
	f.observe(sample{SK: 9, BytesAcked: 1, LPort: 40003, DPort: 443, Dst: pg}, t0)
	f.endPass(map[uint64]bool{})
	if len(f.last) != 0 {
		t.Errorf("unlisted socket kept: %v", f.last)
	}
}

func TestConnectQuantile(t *testing.T) {
	// NET-U-P3: bucket i holds [2^i, 2^(i+1)) us. 90 connects near 1 ms
	// (bucket 9: 512-1023 us) and 10 near 50 ms (bucket 15: 32-65 ms).
	b := make([]uint64, 24)
	b[9], b[15] = 90, 10
	if p50, _ := connectQuantile(b, 0.5); p50 != 1.024 {
		t.Errorf("p50 = %v", p50)
	}
	if p95, _ := connectQuantile(b, 0.95); p95 != 65.536 {
		t.Errorf("p95 = %v", p95)
	}
	if _, ok := connectQuantile(make([]uint64, 24), 0.5); ok {
		t.Error("empty histogram has a quantile")
	}
}

var resolver = netip.MustParseAddr("10.96.0.10")

func dnsGauges(m *dnsMatcher) map[string]float64 {
	out := map[string]float64{}
	m.emit(func(name string, v float64, l map[string]string) { out[name+"|"+l["resolver"]+"|"+l["reason"]] = v })
	return out
}

func TestDNSMatcher(t *testing.T) {
	m := newDNSMatcher()
	q := func(ts uint64, port, id uint16) dnsHeader {
		return dnsHeader{TsNS: ts, Resolver: resolver, ClientPort: port, TxID: id}
	}
	r := func(ts uint64, port, id, flags uint16) dnsHeader {
		return dnsHeader{TsNS: ts, Resolver: resolver, ClientPort: port, TxID: id, Flags: 0x8000 | flags, Response: true}
	}
	// NET-U-P5 and F8: a query sent twice and answered after 12 ms (from the first send).
	m.observe(q(1_000_000, 5000, 1))
	m.observe(q(6_000_000, 5000, 1))
	m.observe(r(13_000_000, 5000, 1, 0))
	m.observe(r(14_000_000, 5000, 1, 0)) // duplicate response: no query left
	// NET-U-F5, F6, F7: NXDOMAIN, empty NOERROR and truncated are not failures.
	m.observe(q(0, 5001, 2))
	m.observe(r(2_000_000, 5001, 2, 3))
	m.observe(q(0, 5002, 3))
	m.observe(r(2_000_000, 5002, 3, 0x0200|2))
	// SERVFAIL and REFUSED are.
	m.observe(q(0, 5003, 4))
	m.observe(r(1_000_000, 5003, 4, 2))
	m.observe(q(0, 5004, 5))
	m.observe(r(1_000_000, 5004, 5, 5))
	// NET-U-F9: a response with no query is dropped.
	m.observe(r(1_000_000, 6000, 99, 2))
	// NET-U-P6: no answer within 5 s is a timeout.
	m.observe(q(0, 5005, 6))
	m.expire(4_000_000_000)
	if len(m.pending) != 1 {
		t.Fatalf("expired too early: %v", m.pending)
	}
	m.expire(5_000_000_000)

	g := dnsGauges(m)
	want := map[string]float64{
		"lighthouse_ebpf_dns_queries_total|10.96.0.10|":          6,
		"lighthouse_ebpf_dns_failures_total|10.96.0.10|servfail": 1,
		"lighthouse_ebpf_dns_failures_total|10.96.0.10|refused":  1,
		"lighthouse_ebpf_dns_failures_total|10.96.0.10|timeout":  1,
		"lighthouse_ebpf_dns_latency_ms|10.96.0.10|":             (12 + 2 + 2) / 3.0,
	}
	if len(g) != len(want) {
		t.Fatalf("got %v, want %v", g, want)
	}
	for k, v := range want {
		if g[k] != v {
			t.Errorf("%s = %v, want %v", k, g[k], v)
		}
	}
}

func TestDNSMatcher_ResolverCap(t *testing.T) {
	m := newDNSMatcher()
	for i := range 8 {
		m.observe(dnsHeader{Resolver: netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), ClientPort: 1, TxID: uint16(i)})
	}
	g := dnsGauges(m)
	if len(m.resolvers) != ebpf.Quota().Resolvers+1 || g["lighthouse_ebpf_dns_queries_total|other|"] != 3 {
		t.Fatalf("cap: %d resolvers, other=%v", len(m.resolvers), g["lighthouse_ebpf_dns_queries_total|other|"])
	}
}

// PRC-U-P6: socket byte deltas go to the owner's usage group, inbound
// (accepted) sockets included, and inbound sockets make no flow.
func TestFlows_Usage(t *testing.T) {
	f := newFlows()
	got := map[string]uint64{}
	f.usage = func(g string, b uint64) { got[g] += b }
	f.observe(sample{SK: 1, BytesAcked: 1000, BytesReceived: 200, LPort: 40000, DPort: 5432, Dst: pg, Src: "exe:/opt/app", Group: "process:app"}, t0)
	f.observe(sample{SK: 2, BytesAcked: 9000, BytesReceived: 100, LPort: 443, DPort: 51000, Dst: netip.MustParseAddr("203.0.113.9"), Src: "exe:/usr/sbin/nginx", Group: "unit:nginx.service", Inbound: true}, t0)
	f.observe(sample{SK: 2, BytesAcked: 9500, BytesReceived: 100, LPort: 443, DPort: 51000, Dst: netip.MustParseAddr("203.0.113.9"), Src: "exe:/usr/sbin/nginx", Group: "unit:nginx.service", Inbound: true}, t0)
	if got["process:app"] != 1200 || got["unit:nginx.service"] != 9600 {
		t.Fatalf("usage: %v", got)
	}
	g := gauges(f)
	if _, ok := g["lighthouse_ebpf_flow_bytes_sent_total|203.0.113.9:51000"]; ok {
		t.Errorf("inbound socket made a flow: %v", g)
	}
}
