package traces

import (
	"cmp"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"
)

// ReceiverAddr is where OBI exports traces: loopback only, and in the
// Kubernetes packaging the pod's own loopback.
const ReceiverAddr = "127.0.0.1:19401"

// TokenHeader carries the receiver token.
const TokenHeader = "X-Lighthouse-Traces-Token"

const (
	// sampleWindow is how long a trace's spans wait for the decision.
	sampleWindow = 10 * time.Second
	// decidedTTL keeps a decision for late spans (TRC-U-F7).
	decidedTTL = time.Minute
	// maxPending bounds spans awaiting a decision (about 25 MiB); beyond
	// it new spans are dropped and counted, except failed ones, which
	// may fill up to twice the cap.
	maxPending = 50_000
	// slowFallback is the "slow" bar before a service has a p99.
	slowFallback   = time.Second
	minSlowSamples = 100
	durWindow     = 200
	burstSpans    = 50
)

// Pipeline takes OBI's spans, filters them, tags them with this host's
// identities and tail-samples per trace before handing them to the
// Exporter (status-harbor docs/eBPF/11-traces.md, "OBI traces").
type Pipeline struct {
	exp  *Exporter
	host string
	// Resolve maps OBI's service.instance.id ("host:pid") to the plan 03
	// service identity (statusharbor.service); nil leaves it unset.
	Resolve func(ctx context.Context, instance, serviceName string) string
	// Token, when set, must arrive in TokenHeader. A header without a
	// space in its value: OBI sends OTEL_EXPORTER_OTLP_TRACES_HEADERS
	// values without percent-decoding them.
	Token string

	on atomic.Bool
	// samplePercent is the share of ordinary traces kept (0..100).
	samplePercent atomic.Int32

	mu        sync.Mutex
	budget    *rate.Limiter
	pending   map[string]*pendingTrace
	nPending  int
	decided   map[string]decision
	checks    map[string]time.Time // trace IDs of recent check runs
	durations map[string][]time.Duration
	counts    map[string]uint64 // kept_<reason> / dropped_<reason>
}

type pendingTrace struct {
	first time.Time
	items []item
}

type decision struct {
	keep bool
	at   time.Time
}

// NewPipeline: perSecond is the host's span budget (bursts to 50).
func NewPipeline(exp *Exporter, host string, perSecond int) *Pipeline {
	p := &Pipeline{
		exp: exp, host: host,
		budget:    rate.NewLimiter(rate.Limit(max(perSecond, 1)), burstSpans),
		pending:   map[string]*pendingTrace{},
		decided:   map[string]decision{},
		checks:    map[string]time.Time{},
		durations: map[string][]time.Duration{},
		counts:    map[string]uint64{},
	}
	p.samplePercent.Store(100)
	return p
}

// NewToken is a random receiver token for a supervised OBI.
func NewToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// SetGate follows the Console's traces gate. samplePercent is clamped to
// 0..100.
func (p *Pipeline) SetGate(services bool, perSecond, samplePercent int) {
	if p == nil {
		return
	}
	p.on.Store(services)
	p.samplePercent.Store(int32(min(max(samplePercent, 0), 100)))
	if perSecond > 0 {
		p.mu.Lock()
		p.budget.SetLimit(rate.Limit(perSecond))
		p.mu.Unlock()
	}
}

// Enabled reports whether service traces are on.
func (p *Pipeline) Enabled() bool { return p != nil && p.on.Load() }

// MarkCheck records a check run's trace ID: the target's spans in that
// trace are always kept.
func (p *Pipeline) MarkCheck(id [16]byte) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.checks[hex.EncodeToString(id[:])] = time.Now()
	p.mu.Unlock()
}

// ServeHTTP is the OTLP/HTTP protobuf receiver.
func (p *Pipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/traces" {
		http.NotFound(w, r)
		return
	}
	if p.Token != "" {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get(TokenHeader)), []byte(p.Token)) != 1 {
			slog.Debug("traces receiver: bad token")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	var rd io.Reader = http.MaxBytesReader(w, r.Body, 8<<20)
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(rd)
		if err != nil {
			http.Error(w, "bad gzip", http.StatusBadRequest)
			return
		}
		defer func() { _ = gz.Close() }()
		rd = gz
	}
	body, err := io.ReadAll(io.LimitReader(rd, 32<<20))
	if err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	var td tracepb.TracesData
	if err := proto.Unmarshal(body, &td); err != nil {
		slog.Debug("traces receiver: undecodable body", "content_type", r.Header.Get("Content-Type"), "error", err)
		http.Error(w, "not OTLP traces", http.StatusBadRequest)
		return
	}
	if p.Enabled() {
		p.Ingest(r.Context(), &td, time.Now())
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
}

// Ingest filters, tags and queues spans for the sampling decision.
func (p *Pipeline) Ingest(ctx context.Context, td *tracepb.TracesData, now time.Time) {
	var filtered uint64
	type tagged struct {
		res   *resourcepb.Resource
		key   string
		spans []*tracepb.Span
	}
	var batch []tagged
	for _, rs := range td.ResourceSpans {
		res, key := p.resource(ctx, rs.Resource)
		var spans []*tracepb.Span
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				filtered += uint64(filterSpan(sp))
				spans = append(spans, sp)
			}
		}
		batch = append(batch, tagged{res, key, spans})
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.counts["filtered_attributes"] += filtered
	for _, b := range batch {
		for _, sp := range b.spans {
			if sp.Kind == tracepb.Span_SPAN_KIND_SERVER {
				p.observe(b.key, spanDuration(sp))
			}
			id := hex.EncodeToString(sp.TraceId)
			if d, ok := p.decided[id]; ok {
				if d.keep {
					p.exp.Add(b.res, sp)
					p.counts["kept_late"]++
				} else {
					p.counts["dropped_late"]++
				}
				continue
			}
			pt := p.pending[id]
			if p.nPending >= maxPending && (!spanFailed(sp) || p.nPending >= 2*maxPending) {
				p.counts["dropped_overflow"]++
				continue
			}
			if pt == nil {
				pt = &pendingTrace{first: now}
				p.pending[id] = pt
			}
			pt.items = append(pt.items, item{b.res, sp})
			p.nPending++
		}
	}
}

// resource replaces OBI's resource: service.name and language survive;
// the host and the plan 03 identity are added. Resources are shared per
// (service, identity) so a batch groups them.
func (p *Pipeline) resource(ctx context.Context, in *resourcepb.Resource) (*resourcepb.Resource, string) {
	var name, instance, lang string
	if in != nil {
		for _, kv := range in.Attributes {
			switch kv.Key {
			case "service.name":
				name = kv.Value.GetStringValue()
			case "service.instance.id":
				instance = kv.Value.GetStringValue()
			case "telemetry.sdk.language":
				lang = kv.Value.GetStringValue()
			}
		}
	}
	identity := ""
	if p.Resolve != nil && instance != "" {
		identity = p.Resolve(ctx, instance, name)
	}
	if name == "" {
		name = identity
	}
	attrs := []*commonpb.KeyValue{Str("service.name", name), Str("statusharbor.host", p.host)}
	if identity != "" {
		attrs = append(attrs, Str("statusharbor.service", identity))
	}
	if lang != "" {
		attrs = append(attrs, Str("telemetry.sdk.language", lang))
	}
	return &resourcepb.Resource{Attributes: attrs}, name + "|" + identity
}

func spanDuration(sp *tracepb.Span) time.Duration {
	if sp.EndTimeUnixNano < sp.StartTimeUnixNano {
		return 0
	}
	return time.Duration(sp.EndTimeUnixNano - sp.StartTimeUnixNano)
}

// observe keeps a rolling window of a service's server span durations.
func (p *Pipeline) observe(key string, d time.Duration) {
	w := append(p.durations[key], d)
	if len(w) > durWindow {
		w = w[len(w)-durWindow:]
	}
	p.durations[key] = w
}

// slowBar is the service's p99 server span duration: a share of traffic
// rare enough that keeping it first does not crowd out the sample.
func (p *Pipeline) slowBar(key string) time.Duration {
	w := p.durations[key]
	if len(w) < minSlowSamples {
		return slowFallback
	}
	s := slices.Clone(w)
	slices.Sort(s)
	return s[len(s)*99/100]
}

// Run decides traces whose window has passed, once a second.
func (p *Pipeline) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	report := time.NewTicker(time.Minute)
	defer report.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			p.Decide(now)
		case <-report.C:
			if p.Enabled() {
				slog.Debug("traces pipeline", "counts", p.Counts(), "export_dropped", p.exp.Dropped())
			}
		}
	}
}

// Decide applies the sampling rules to traces older than the window, in
// priority order so the budget goes to the most useful traces first:
//
//   - check and error traces are always kept, and still spend budget;
//   - slow traces (above the service's p99) are kept while budget lasts;
//   - of the rest, the sample rate's share (chosen by trace ID) is kept
//     while budget is left after them.
//
// Within a priority, older traces go first.
func (p *Pipeline) Decide(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	type due struct {
		id     string
		pt     *pendingTrace
		reason string
		rank   int
	}
	var ready []due
	for id, pt := range p.pending {
		if now.Sub(pt.first) < sampleWindow {
			continue
		}
		reason := p.reason(id, pt)
		rank := map[string]int{"check": 0, "error": 0, "slow": 1, "": 2}[reason]
		ready = append(ready, due{id, pt, reason, rank})
	}
	slices.SortFunc(ready, func(a, b due) int {
		return cmp.Or(cmp.Compare(a.rank, b.rank), a.pt.first.Compare(b.pt.first))
	})
	for _, d := range ready {
		n := len(d.pt.items)
		keep, reason := false, d.reason
		switch d.rank {
		case 0:
			p.budget.ReserveN(now, n)
			keep = true
		case 2:
			if !sampledIn(d.pt.items[0].span.TraceId, int(p.samplePercent.Load())) {
				p.counts["dropped_sample"] += uint64(n)
				p.decided[d.id] = decision{keep: false, at: now}
				p.nPending -= n
				delete(p.pending, d.id)
				continue
			}
			keep, reason = p.budget.AllowN(now, n), "sampled"
		default:
			keep = p.budget.AllowN(now, n)
			if reason == "" {
				reason = "sampled"
			}
		}
		if keep {
			for _, it := range d.pt.items {
				p.exp.Add(it.res, it.span)
			}
			p.counts["kept_"+reason] += uint64(n)
		} else {
			p.counts["dropped_budget"] += uint64(n)
		}
		p.decided[d.id] = decision{keep: keep, at: now}
		p.nPending -= n
		delete(p.pending, d.id)
	}
	for id, d := range p.decided {
		if now.Sub(d.at) > decidedTTL {
			delete(p.decided, id)
		}
	}
	for id, at := range p.checks {
		if now.Sub(at) > decidedTTL {
			delete(p.checks, id)
		}
	}
}

// sampledIn decides by trace ID, so every host makes the same choice for
// a trace that crosses hosts. W3C trace IDs are random in their low
// bytes.
func sampledIn(traceID []byte, percent int) bool {
	if percent >= 100 {
		return true
	}
	if percent <= 0 || len(traceID) < 8 {
		return false
	}
	return binary.BigEndian.Uint64(traceID[len(traceID)-8:])%100 < uint64(percent)
}

func (p *Pipeline) reason(id string, pt *pendingTrace) string {
	if _, ok := p.checks[id]; ok {
		return "check"
	}
	slow := false
	for _, it := range pt.items {
		if spanFailed(it.span) {
			return "error"
		}
		if it.span.Kind == tracepb.Span_SPAN_KIND_SERVER || len(it.span.ParentSpanId) == 0 {
			if spanDuration(it.span) > p.slowBar(resourceKey(it.res)) {
				slow = true
			}
		}
	}
	if slow {
		return "slow"
	}
	return ""
}

func resourceKey(res *resourcepb.Resource) string {
	return StringAttr(res.Attributes, "service.name") + "|" + StringAttr(res.Attributes, "statusharbor.service")
}

// spanFailed: status error, HTTP 5xx, or a gRPC server error.
func spanFailed(sp *tracepb.Span) bool {
	if sp.Status != nil && sp.Status.Code == tracepb.Status_STATUS_CODE_ERROR {
		return true
	}
	for _, kv := range sp.Attributes {
		switch kv.Key {
		case "http.response.status_code":
			if intValue(kv) >= 500 {
				return true
			}
		case "rpc.grpc.status_code":
			// UNKNOWN, DEADLINE_EXCEEDED, UNIMPLEMENTED, INTERNAL,
			// UNAVAILABLE, DATA_LOSS are server errors.
			switch intValue(kv) {
			case 2, 4, 12, 13, 14, 15:
				return sp.Kind == tracepb.Span_SPAN_KIND_SERVER
			}
		}
	}
	return false
}

func intValue(kv *commonpb.KeyValue) int64 {
	if v, ok := kv.Value.GetValue().(*commonpb.AnyValue_IntValue); ok {
		return v.IntValue
	}
	var n int64
	_, _ = fmt.Sscan(kv.Value.GetStringValue(), &n)
	return n
}

// StringAttr reads a string attribute.
func StringAttr(attrs []*commonpb.KeyValue, key string) string {
	for _, kv := range attrs {
		if kv.Key == key {
			return kv.Value.GetStringValue()
		}
	}
	return ""
}

// Counts returns the kept and dropped span counters by reason.
func (p *Pipeline) Counts() map[string]uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]uint64, len(p.counts))
	for k, v := range p.counts {
		out[k] = v
	}
	return out
}

// StatusDetail is the "traces" status line's detail.
func (p *Pipeline) StatusDetail() string {
	c := p.Counts()
	var kept, dropped uint64
	for k, v := range c {
		switch {
		case strings.HasPrefix(k, "kept_"):
			kept += v
		case strings.HasPrefix(k, "dropped_"):
			dropped += v
		}
	}
	return fmt.Sprintf("%d spans kept, %d dropped since start (%d over budget)", kept, dropped, c["dropped_budget"])
}
