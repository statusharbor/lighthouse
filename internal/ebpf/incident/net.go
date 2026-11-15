package incident

import (
	"net/netip"
	"strconv"
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf"
)

// connKey is one kernel counter key, platform-neutral so the aggregation
// below is tested without a kernel.
type connKey struct {
	Addr  [16]byte
	RPort uint16
	LPort uint16
	IPv6  bool
	Kind  uint8
	Err   uint8
}

const (
	connConnectFailed = 1
	connResetSent     = 2
	connResetReceived = 3
	connRetransmit    = 4
)

var connMetric = map[uint8]string{
	connConnectFailed: "lighthouse_ebpf_tcp_connect_failures_total",
	connResetSent:     "lighthouse_ebpf_tcp_resets_sent_total",
	connResetReceived: "lighthouse_ebpf_tcp_resets_received_total",
	connRetransmit:    "lighthouse_ebpf_tcp_retransmits_total",
}

// ConnectReason names a failed connect's socket error. 0 means the
// application closed the socket before the handshake finished, usually
// its own connect timeout.
func ConnectReason(errno uint8) string {
	switch errno {
	case 111: // ECONNREFUSED
		return "refused"
	case 110: // ETIMEDOUT
		return "timed_out"
	case 113, 101: // EHOSTUNREACH, ENETUNREACH
		return "unreachable"
	case 0:
		return "aborted"
	}
	return "other"
}

// ponytail: Linux's default ephemeral range, not the host's sysctl (the
// agent may sit in another network namespace). Read it if hosts tune it.
func ephemeral(p uint16) bool { return p >= 32768 && p <= 60999 }

type series struct {
	metric, peer, port, direction, reason string
}

func (s series) labels() map[string]string {
	l := map[string]string{"port": s.port, "direction": s.direction}
	if s.peer != "" {
		l["peer"] = s.peer
	}
	if s.reason != "" {
		l["reason"] = s.reason
	}
	return l
}

// seriesFor folds a socket into a low-cardinality series. Outbound
// sockets keep the peer address and port. Inbound ones (a server port
// talking to a client's ephemeral port) keep only the local port, since
// their peers are arbitrary clients.
func seriesFor(k connKey) (series, bool) {
	metric, ok := connMetric[k.Kind]
	if !ok {
		return series{}, false
	}
	s := series{metric: metric, direction: "out"}
	if k.Kind == connConnectFailed {
		s.reason = ConnectReason(k.Err)
	}
	if k.Kind != connConnectFailed && ephemeral(k.RPort) && !ephemeral(k.LPort) {
		s.direction, s.port = "in", itoa(k.LPort)
		return s, true
	}
	addr := netip.AddrFrom16(k.Addr)
	if !k.IPv6 {
		addr = netip.AddrFrom4([4]byte(k.Addr[:4]))
	}
	s.peer, s.port = addr.Unmap().String(), itoa(k.RPort)
	return s, true
}

func itoa(p uint16) string { return strconv.Itoa(int(p)) }

// netTotals keeps cumulative counts per series. The kernel map is drained
// every interval, so the totals here are what goes out as counters.
// Series idle for an hour are dropped; past maxSeries new series are
// refused and counted.
type netTotals struct {
	maxSeries int // 0: four series (one per counter) per destination of the quota
	public    ebpf.PublicLimiter
	idle      time.Duration
	totals    map[series]*total
	refused   uint64
}

type total struct {
	n    uint64
	seen time.Time
}

func newNetTotals() *netTotals {
	return &netTotals{idle: time.Hour, totals: map[series]*total{}}
}

func (t *netTotals) add(k connKey, n uint64, now time.Time) {
	s, ok := seriesFor(k)
	if !ok {
		return
	}
	if s.peer != "" {
		s.peer = t.public.Name(netip.MustParseAddr(s.peer), s.port)
	}
	cur := t.totals[s]
	if cur == nil {
		limit := t.maxSeries
		if limit == 0 {
			limit = 4 * ebpf.Quota().Destinations
		}
		if len(t.totals) >= limit {
			t.refused++
			return
		}
		cur = &total{}
		t.totals[s] = cur
	}
	cur.n += n
	cur.seen = now
}

// emit reports every live series and forgets idle ones.
func (t *netTotals) emit(now time.Time, gauge func(name string, value float64, labels map[string]string)) {
	for s, cur := range t.totals {
		if now.Sub(cur.seen) > t.idle {
			delete(t.totals, s)
			continue
		}
		gauge(s.metric, float64(cur.n), s.labels())
	}
	gauge("lighthouse_ebpf_tcp_series_refused_total", float64(t.refused), nil)
}
