package network

import (
	"net/netip"
	"strconv"
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf"
)

// sample is one socket's counters from the iterator or at close,
// platform-neutral so the delta and aggregation rules are tested without
// a kernel.
type sample struct {
	SK            uint64
	BytesAcked    uint64 // bytes sent and acknowledged
	BytesReceived uint64
	SRTTus        uint32
	Retrans       uint32
	SegsOut       uint32
	LPort, DPort  uint16
	Dst           netip.Addr
	Src           string // service identity; "" when the owner is unknown
	Group         string // usage group of the owner (plan 05); "" when unknown
	Closed        bool
	Inbound       bool // accepted by a local server
}

type flowKey struct {
	Src, Dst string
	Port     uint16
}

// interval is one flow's activity in the current interval.
type interval struct {
	rttSum  float64
	rttN    int
	retrans uint64
	segs    uint64
}

// minSegmentsForRatio: below this many data segments in an interval the
// retransmit ratio is noise (1 of 3 is not 33% loss, NET-U-F3).
const minSegmentsForRatio = 100

// flows turns socket counters into per-flow series: deltas against the
// last value per socket, interval RTT and retransmit ratio, and running
// byte totals. At most maxFlows flows; the rest are counted.
type flows struct {
	maxFlows  int // 0: the destinations quota
	public    ebpf.PublicLimiter
	idle      time.Duration
	last      map[uint64]sample
	cur       map[flowKey]*interval
	bytesOut  map[flowKey]*total
	bytesIn   map[flowKey]uint64
	truncated uint64
	// usage receives every owned socket's byte delta, inbound included,
	// for per-process network attribution (plan 05). Nil: not reported.
	usage func(group string, bytes uint64)
}

type total struct {
	n    uint64
	seen time.Time
}

func newFlows() *flows {
	return &flows{
		idle: time.Hour, last: map[uint64]sample{}, cur: map[flowKey]*interval{},
		bytesOut: map[flowKey]*total{}, bytesIn: map[flowKey]uint64{},
	}
}

// outbound decides which sockets are dependencies: ones whose connect the
// agent saw, or, for sockets older than the agent, a service port reached
// from an ephemeral port. Server-side sockets are left out.
func outbound(s sample) bool {
	return !s.Inbound && (s.Src != "" || (s.DPort < 32768 && s.LPort >= 32768))
}

// observe takes one socket reading. The first sighting of a socket only
// sets its baseline (NET-U-F1), unless the agent saw its connect, in which
// case its whole life is new. Counters that went down mean the kernel
// reused the address for a new socket (NET-U-F2): a new baseline.
func (f *flows) observe(s sample, now time.Time) {
	s.Dst = s.Dst.Unmap() // NET-U-P7
	if s.Dst.IsLoopback() || (!outbound(s) && (f.usage == nil || s.Group == "")) {
		delete(f.last, s.SK)
		return
	}
	prev, seen := f.last[s.SK]
	if seen && (s.BytesAcked < prev.BytesAcked || s.SegsOut < prev.SegsOut || s.BytesReceived < prev.BytesReceived) {
		seen = false
	}
	if s.Closed {
		delete(f.last, s.SK)
	} else {
		f.last[s.SK] = s
	}
	if !seen {
		if s.Src == "" {
			return
		}
		prev = sample{}
	}
	dAcked, dRecv := s.BytesAcked-prev.BytesAcked, s.BytesReceived-prev.BytesReceived
	if f.usage != nil && s.Group != "" && dAcked+dRecv > 0 {
		f.usage(s.Group, dAcked+dRecv) // PRC-U-P6
	}
	if !outbound(s) {
		return
	}
	src := s.Src
	if src == "" {
		src = "unknown"
	}
	k := flowKey{Src: src, Dst: f.public.Name(s.Dst, strconv.Itoa(int(s.DPort))), Port: s.DPort}
	cur := f.cur[k]
	if cur == nil {
		limit := f.maxFlows
		if limit == 0 {
			limit = ebpf.Quota().Destinations
		}
		if _, known := f.bytesOut[k]; !known && len(f.bytesOut) >= limit {
			f.truncated++
			return
		}
		cur = &interval{}
		f.cur[k] = cur
	}
	if dAcked > 0 && s.SRTTus > 0 { // RTT only when data moved (NET-U-F4)
		cur.rttSum += float64(s.SRTTus) / 1000 // NET-U-P1: microseconds to ms
		cur.rttN++
	}
	cur.retrans += uint64(s.Retrans - prev.Retrans)
	cur.segs += uint64(s.SegsOut - prev.SegsOut)
	t := f.bytesOut[k]
	if t == nil {
		t = &total{}
		f.bytesOut[k] = t
	}
	t.n += dAcked
	t.seen = now
	f.bytesIn[k] += dRecv
}

// endPass forgets sockets the iterator no longer lists (their close event
// was lost) so their entries do not grow without bound (NET-E-F4).
func (f *flows) endPass(listed map[uint64]bool) {
	for sk := range f.last {
		if !listed[sk] {
			delete(f.last, sk)
		}
	}
}

// emit reports the interval's RTT and retransmit ratio and the running
// byte totals, then starts a new interval.
func (f *flows) emit(now time.Time, gauge func(name string, value float64, labels map[string]string)) {
	labels := func(k flowKey) map[string]string {
		return map[string]string{"src": k.Src, "dst": k.Dst, "dst_port": strconv.Itoa(int(k.Port))}
	}
	for k, c := range f.cur {
		if c.rttN > 0 {
			gauge("lighthouse_ebpf_flow_rtt_ms", c.rttSum/float64(c.rttN), labels(k))
		}
		if c.segs >= minSegmentsForRatio {
			gauge("lighthouse_ebpf_flow_retransmit_ratio", float64(c.retrans)/float64(c.segs), labels(k))
		}
	}
	for k, t := range f.bytesOut {
		if now.Sub(t.seen) > f.idle {
			delete(f.bytesOut, k)
			delete(f.bytesIn, k)
			continue
		}
		gauge("lighthouse_ebpf_flow_bytes_sent_total", float64(t.n), labels(k))
		gauge("lighthouse_ebpf_flow_bytes_received_total", float64(f.bytesIn[k]), labels(k))
	}
	gauge("lighthouse_ebpf_flow_quality_truncated_total", float64(f.truncated), nil)
	f.cur = map[flowKey]*interval{}
}

// connectQuantile returns the upper bound in ms of the bucket holding the
// q-th connect duration; bucket i holds [2^i, 2^(i+1)) microseconds.
func connectQuantile(buckets []uint64, q float64) (float64, bool) {
	var n uint64
	for _, b := range buckets {
		n += b
	}
	if n == 0 {
		return 0, false
	}
	rank := uint64(q*float64(n-1)) + 1
	var seen uint64
	for i, b := range buckets {
		seen += b
		if seen >= rank {
			return float64(uint64(1)<<(i+1)) / 1000, true
		}
	}
	return 0, false
}
