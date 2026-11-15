package agent

import (
	"encoding/json"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf"
	"github.com/statusharbor/lighthouse/internal/traces"
	"github.com/statusharbor/lighthouse/internal/transport"
)

// ebpfController is the part of *ebpf.Manager the runner drives: remote
// flags in from heartbeat responses, the status report out on heartbeats.
type ebpfController interface {
	Apply(enabled []string)
	Statuses() []ebpf.Status
}

// SetEBPF attaches the eBPF manager. Nil (the default) means this agent
// runs no eBPF collectors and reports no eBPF status.
func (r *Runner) SetEBPF(c ebpfController) { r.ebpf = c }

// SetTracesGate registers what follows the Console's traces gate
// (status-harbor docs/eBPF/11-traces.md); ApplyTracesGate calls it.
func (r *Runner) SetTracesGate(fn func(*transport.TracesGate)) { r.tracesGate = fn }

// ApplyTracesGate hands a /register or /heartbeat traces gate on; nil
// means off.
func (r *Runner) ApplyTracesGate(g *transport.TracesGate) {
	if r.tracesGate != nil {
		r.tracesGate(g)
	}
}

// ApplyEBPFGate passes the remote flags to the manager. A nil gate turns
// every collector off.
func (r *Runner) ApplyEBPFGate(g *transport.EBPFGate) {
	if r.ebpf == nil {
		return
	}
	var enabled, limited []string
	var q *ebpf.Quotas
	if g != nil {
		enabled, limited = g.Collectors, g.Limited
		if g.Quotas != nil {
			v := ebpf.Quotas(*g.Quotas)
			q = &v
		}
	}
	ebpf.SetQuotas(q)
	ebpf.SetLimited(limited)
	r.ebpf.Apply(enabled)
}

// pendingEBPFStatus returns the status report when it differs from the
// last one a heartbeat delivered, nil otherwise.
func (r *Runner) pendingEBPFStatus() []transport.EBPFStatus {
	if r.ebpf == nil {
		return nil
	}
	sts := r.ebpf.Statuses()
	out := make([]transport.EBPFStatus, len(sts))
	for i, s := range sts {
		out[i] = transport.EBPFStatus{Collector: s.Collector, State: string(s.State), Reason: string(s.Reason), Detail: s.Detail}
	}
	if r.tracesPipeline != nil {
		out = append(out, tracesStatus(out, r.tracesPipeline.Enabled()))
	}
	if slices.Equal(out, r.ebpfAcked) {
		return nil
	}
	return out
}

// tracesStatus is the "traces" line (status-harbor docs/eBPF/11-traces.md):
// OBI's spans flow while traces are on and Real traffic runs, so the line
// follows the requests collector. Counts stay out of it so the report only
// changes when the state does.
func tracesStatus(sts []transport.EBPFStatus, on bool) transport.EBPFStatus {
	if !on {
		return transport.EBPFStatus{Collector: "traces", State: string(ebpf.StateDisabled), Reason: string(ebpf.ReasonRemoteOff)}
	}
	for _, s := range sts {
		if s.Collector == "requests" {
			s.Collector = "traces"
			return s
		}
	}
	return transport.EBPFStatus{Collector: "traces", State: string(ebpf.StateDisabled), Reason: string(ebpf.ReasonRemoteOff)}
}

// SetTracesPipeline lets the status report include the traces line.
func (r *Runner) SetTracesPipeline(p *traces.Pipeline) { r.tracesPipeline = p }

// ebpfSink adapts collector output to the agent's pipes. Gauges are kept
// as the latest value per series and go out with the next host-metrics
// push (it is an agent.Collector for that). Collectors re-report live
// series every interval, so a series not reported for gaugeTTL is gone
// (stopped collector, idle TCP peer) and is dropped. Events are wrapped in an
// envelope and queued on the batcher, which ships them to the events
// endpoint without ever blocking the collector.
type ebpfSink struct {
	hostID, bootID string
	batcher        *ebpf.Batcher

	mu           sync.Mutex
	gauges       map[string]transport.HostSample
	encodeErrors atomic.Uint64
	notAllowed   atomic.Uint64 // series or events outside the allow-list

	// Daily quotas (plan 07): events per day and new series per day.
	// known is every series admitted, reset each UTC day to the live ones.
	day                       string
	eventsToday, seriesToday  int
	known                     map[string]bool
	eventsDropped, seriesDrop uint64
}

func newEBPFSink(hostID, bootID string, b *ebpf.Batcher) *ebpfSink {
	return &ebpfSink{hostID: hostID, bootID: bootID, batcher: b, gauges: map[string]transport.HostSample{}, known: map[string]bool{}}
}

// forCollector is the Manager's sink factory.
func (s *ebpfSink) forCollector(name string) ebpf.Sink { return collectorSink{s, name} }

type collectorSink struct {
	s    *ebpfSink
	name string
}

func (c collectorSink) Gauge(name string, value float64, labels map[string]string) {
	if !allowedSeries(name, labels) {
		c.s.notAllowed.Add(1)
		return
	}
	key := name
	for _, k := range slices.Sorted(maps.Keys(labels)) {
		key += "\x00" + k + "=" + labels[k]
	}
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	c.s.rollDay(time.Now())
	if !c.s.known[key] {
		if c.s.seriesToday >= ebpf.Quota().NewSeriesPerDay {
			c.s.seriesDrop++
			return
		}
		c.s.seriesToday++
		c.s.known[key] = true
	}
	c.s.gauges[key] = transport.HostSample{Name: name, Labels: labels, Value: value, Timestamp: time.Now().UnixMilli()}
}

// rollDay starts a new quota day: today's counters reset, and the series
// alive now stay known so they are not counted as new again.
func (s *ebpfSink) rollDay(now time.Time) {
	day := now.UTC().Format(time.DateOnly)
	if day == s.day {
		return
	}
	s.day, s.eventsToday, s.seriesToday = day, 0, 0
	s.known = make(map[string]bool, len(s.gauges))
	for k := range s.gauges {
		s.known[k] = true
	}
}

func (c collectorSink) Event(kind string, at time.Time, payload any) {
	c.s.mu.Lock()
	c.s.rollDay(time.Now())
	if c.s.eventsToday >= ebpf.Quota().EventsPerDay {
		c.s.eventsDropped++
		c.s.mu.Unlock()
		return
	}
	c.s.eventsToday++
	c.s.mu.Unlock()
	raw, err := json.Marshal(payload)
	if err != nil {
		c.s.encodeErrors.Add(1)
		return
	}
	raw, ok := filterEvent(kind, raw)
	if !ok {
		c.s.notAllowed.Add(1)
		return
	}
	c.s.batcher.Add(transport.EBPFEnvelope{
		Schema: ebpf.SchemaVersion, HostID: c.s.hostID, BootID: c.s.bootID,
		Collector: c.name, Kind: kind, Time: at.UTC(), Payload: raw,
	})
}

const gaugeTTL = 5 * time.Minute

func (s *ebpfSink) Collect() ([]transport.HostSample, error) {
	now := time.Now().UnixMilli()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]transport.HostSample, 0, len(s.gauges)+2)
	for k, g := range s.gauges {
		if now-g.Timestamp > gaugeTTL.Milliseconds() {
			delete(s.gauges, k)
			continue
		}
		out = append(out, g)
	}
	return append(out,
		transport.HostSample{Name: "lighthouse_ebpf_events_dropped_total", Value: float64(s.batcher.Dropped()), Timestamp: now},
		transport.HostSample{Name: "lighthouse_ebpf_events_encode_errors_total", Value: float64(s.encodeErrors.Load()), Timestamp: now},
		transport.HostSample{Name: "lighthouse_ebpf_events_quota_dropped_total", Value: float64(s.eventsDropped), Timestamp: now},
		transport.HostSample{Name: "lighthouse_ebpf_series_quota_dropped_total", Value: float64(s.seriesDrop), Timestamp: now},
		transport.HostSample{Name: "lighthouse_ebpf_series_not_allowed_total", Value: float64(s.notAllowed.Load()), Timestamp: now},
	), nil
}
