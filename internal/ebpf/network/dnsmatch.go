package network

import (
	"net/netip"

	"github.com/statusharbor/lighthouse/internal/ebpf"
)

// dnsHeader is one DNS header the kernel saw on port 53.
type dnsHeader struct {
	TsNS       uint64 // monotonic
	Resolver   netip.Addr
	ClientPort uint16
	TxID       uint16
	Flags      uint16
	Response   bool
}

const (
	dnsTimeoutNS = 5_000_000_000 // unanswered queries are timeouts after 5 s (NET-U-P6)
	maxPending   = 4096
)

type dnsKey struct {
	Resolver netip.Addr
	Port     uint16
	TxID     uint16
}

type resolverStats struct {
	queries    uint64
	failures   map[string]uint64 // servfail, refused, timeout, other
	latencySum float64           // this interval, ms
	latencyN   int
}

// dnsMatcher pairs queries with responses per resolver, client port and
// transaction ID.
type dnsMatcher struct {
	pending   map[dnsKey]uint64 // first send time
	resolvers map[string]*resolverStats
}

func newDNSMatcher() *dnsMatcher {
	return &dnsMatcher{pending: map[dnsKey]uint64{}, resolvers: map[string]*resolverStats{}}
}

func (m *dnsMatcher) stats(r netip.Addr) *resolverStats {
	name := r.Unmap().String()
	s := m.resolvers[name]
	if s == nil {
		if len(m.resolvers) >= ebpf.Quota().Resolvers {
			name = "other"
			if s = m.resolvers[name]; s != nil {
				return s
			}
		}
		s = &resolverStats{failures: map[string]uint64{}}
		m.resolvers[name] = s
	}
	return s
}

// failure classifies a response: NOERROR (with or without records,
// NET-U-F6) and NXDOMAIN (search-domain expansion, NET-U-F5) are answers,
// and so is a truncated answer the client retries over TCP (NET-U-F7).
func failure(flags uint16) string {
	if flags&0x0200 != 0 {
		return ""
	}
	switch flags & 0x000f {
	case 0, 3:
		return ""
	case 2:
		return "servfail"
	case 5:
		return "refused"
	}
	return "other"
}

func (m *dnsMatcher) observe(e dnsHeader) {
	k := dnsKey{Resolver: e.Resolver.Unmap(), Port: e.ClientPort, TxID: e.TxID}
	isResponse := e.Response && e.Flags&0x8000 != 0
	if !isResponse {
		if e.Response {
			return // a query arriving at a local resolver: not ours to time
		}
		if _, ok := m.pending[k]; ok {
			return // a retransmitted query, timed from the first send (NET-U-F8)
		}
		if len(m.pending) >= maxPending {
			return
		}
		m.pending[k] = e.TsNS
		m.stats(k.Resolver).queries++
		return
	}
	sent, ok := m.pending[k]
	if !ok {
		return // no recorded query (NET-U-F9)
	}
	delete(m.pending, k)
	s := m.stats(k.Resolver)
	if f := failure(e.Flags); f != "" {
		s.failures[f]++
		return
	}
	s.latencySum += float64(e.TsNS-sent) / 1e6
	s.latencyN++
}

// expire turns queries unanswered for 5 seconds into timeouts.
func (m *dnsMatcher) expire(nowNS uint64) {
	for k, sent := range m.pending {
		if nowNS-sent >= dnsTimeoutNS {
			delete(m.pending, k)
			m.stats(k.Resolver).failures["timeout"]++
		}
	}
}

func (m *dnsMatcher) emit(gauge func(name string, value float64, labels map[string]string)) {
	for name, s := range m.resolvers {
		gauge("lighthouse_ebpf_dns_queries_total", float64(s.queries), map[string]string{"resolver": name})
		for reason, n := range s.failures {
			gauge("lighthouse_ebpf_dns_failures_total", float64(n), map[string]string{"resolver": name, "reason": reason})
		}
		if s.latencyN > 0 {
			gauge("lighthouse_ebpf_dns_latency_ms", s.latencySum/float64(s.latencyN), map[string]string{"resolver": name})
		}
		s.latencySum, s.latencyN = 0, 0
	}
}
