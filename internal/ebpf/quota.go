package ebpf

import (
	"net/netip"
	"sync"
	"sync/atomic"
)

// Quotas are the per-Lighthouse cardinality limits (docs/eBPF/07-storage.md,
// "Quotas and cardinality"). The Console delivers them with the remote
// flags; collectors read the current values when they admit a new entry
// and fold the rest into "other" with a truncation counter.
type Quotas struct {
	Destinations       int `json:"destinations"`        // flow and edge destinations per host
	PublicDestinations int `json:"public_destinations"` // of those, public internet addresses kept one by one
	Resolvers          int `json:"resolvers"`
	Services           int `json:"services"` // request-metrics services
	Routes             int `json:"routes"`   // per service, "other" included in the series count
	EventsPerDay       int `json:"events_per_day"`
	NewSeriesPerDay    int `json:"new_series_per_day"`
}

// DefaultQuotas are the plan 07 values, used until the Console sends its
// own.
var DefaultQuotas = Quotas{
	Destinations: 200, PublicDestinations: 20, Resolvers: 5, Services: 20, Routes: 50,
	EventsPerDay: 2000, NewSeriesPerDay: 5000,
}

var current atomic.Pointer[Quotas]

var limited atomic.Pointer[map[string]bool]

// SetLimited records the collectors the plan runs in a reduced mode (plan
// 08: "incident" without its network counters on the top-line-only plan).
func SetLimited(names []string) {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	limited.Store(&m)
}

// Limited reports whether a collector runs in its reduced mode.
func Limited(name string) bool {
	if m := limited.Load(); m != nil {
		return (*m)[name]
	}
	return false
}

// SetQuotas applies the Console's values; zero fields keep the defaults.
func SetQuotas(q *Quotas) {
	v := DefaultQuotas
	if q != nil {
		for _, f := range []struct{ dst, src *int }{
			{&v.Destinations, &q.Destinations}, {&v.PublicDestinations, &q.PublicDestinations},
			{&v.Resolvers, &q.Resolvers}, {&v.Services, &q.Services}, {&v.Routes, &q.Routes},
			{&v.EventsPerDay, &q.EventsPerDay}, {&v.NewSeriesPerDay, &q.NewSeriesPerDay},
		} {
			if *f.src > 0 {
				*f.dst = *f.src
			}
		}
	}
	current.Store(&v)
}

// Quota returns the quotas in force.
func Quota() Quotas {
	if q := current.Load(); q != nil {
		return *q
	}
	return DefaultQuotas
}

// PublicLimiter keeps public internet destinations individually only for
// the first PublicDestinations seen; later ones collapse to one entry per
// port ("public:<port>"). Private, loopback and link-local addresses are
// always kept. Safe for concurrent use.
//
// ponytail: first seen, not busiest; ranking needs a window of history.
type PublicLimiter struct {
	mu   sync.Mutex
	kept map[netip.Addr]bool
}

// Name returns how a destination address is stored.
func (p *PublicLimiter) Name(a netip.Addr, port string) string {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return a.String()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.kept == nil {
		p.kept = map[netip.Addr]bool{}
	}
	if p.kept[a] || len(p.kept) < Quota().PublicDestinations {
		p.kept[a] = true
		return a.String()
	}
	return "public:" + port
}
