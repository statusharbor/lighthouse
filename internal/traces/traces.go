// Package traces sends spans to the traces plane (status-harbor
// docs/eBPF/11-traces.md): a span per check run with phase children, and
// later the host's filtered OBI spans. Spans leave in OTLP/HTTP protobuf
// batches to POST /api/lighthouse/v1/traces with the Lighthouse token.
package traces

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/statusharbor/lighthouse/internal/checks"
)

const (
	// Path is the relay route (the Cloudflare Worker forwards it to
	// metrics-service).
	Path = "/api/lighthouse/v1/traces"
	// CheckService is service.name on check spans.
	CheckService = "statusharbor-check"

	batchSpans    = 512
	flushInterval = 10 * time.Second
	// maxBuffered bounds what waits for delivery while the relay is down
	// or refusing (about 10 MiB of spans); the oldest go first.
	// ponytail: memory, not the plan's 32 MiB disk buffer; spans waiting
	// at a restart are lost. Add a disk spool if that loss matters.
	maxBuffered = 40_000
)

type item struct {
	res  *resourcepb.Resource
	span *tracepb.Span
}

// Exporter batches spans and posts them. Add never blocks; Run flushes.
type Exporter struct {
	url, token string
	httpc      *http.Client

	mu      sync.Mutex
	queue   []item
	kick    chan struct{}
	dropped atomic.Uint64
}

func NewExporter(baseURL, token string, httpc *http.Client) *Exporter {
	return &Exporter{url: baseURL + Path, token: token, httpc: httpc, kick: make(chan struct{}, 1)}
}

// Add queues spans that share a resource.
func (e *Exporter) Add(res *resourcepb.Resource, spans ...*tracepb.Span) {
	e.mu.Lock()
	for _, sp := range spans {
		e.queue = append(e.queue, item{res, sp})
	}
	if over := len(e.queue) - maxBuffered; over > 0 {
		e.queue = e.queue[over:]
		e.dropped.Add(uint64(over))
	}
	full := len(e.queue) >= batchSpans
	e.mu.Unlock()
	if full {
		select {
		case e.kick <- struct{}{}:
		default:
		}
	}
}

// Dropped counts spans lost to the buffer cap.
func (e *Exporter) Dropped() uint64 { return e.dropped.Load() }

// Run flushes every flushInterval, or when a batch fills, until ctx ends.
func (e *Exporter) Run(ctx context.Context) {
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.kick:
		}
		for e.Flush(ctx) {
		}
	}
}

// Flush sends one batch; true when it sent a full one and more wait.
// A failed batch goes back to the front of the queue for the next tick.
func (e *Exporter) Flush(ctx context.Context) bool {
	e.mu.Lock()
	n := min(len(e.queue), batchSpans)
	batch := append([]item(nil), e.queue[:n]...)
	e.queue = e.queue[n:]
	e.mu.Unlock()
	if n == 0 {
		return false
	}
	if err := e.post(ctx, batch); err != nil {
		slog.Warn("traces export failed, retrying next flush", "spans", n, "error", err)
		e.mu.Lock()
		e.queue = append(batch, e.queue...)
		if over := len(e.queue) - maxBuffered; over > 0 {
			e.queue = e.queue[over:]
			e.dropped.Add(uint64(over))
		}
		e.mu.Unlock()
		return false
	}
	return n == batchSpans
}

func (e *Exporter) post(ctx context.Context, batch []item) error {
	// TracesData has ExportTraceServiceRequest's wire format (field 1,
	// resource_spans) without the collector package's gRPC dependencies.
	req := &tracepb.TracesData{}
	byRes := map[*resourcepb.Resource]*tracepb.ScopeSpans{}
	for _, it := range batch {
		ss, ok := byRes[it.res]
		if !ok {
			ss = &tracepb.ScopeSpans{Scope: &commonpb.InstrumentationScope{Name: "statusharbor-lighthouse"}}
			byRes[it.res] = ss
			req.ResourceSpans = append(req.ResourceSpans, &tracepb.ResourceSpans{Resource: it.res, ScopeSpans: []*tracepb.ScopeSpans{ss}})
		}
		ss.Spans = append(ss.Spans, it.span)
	}
	body, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("encode spans: %w", err)
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build traces request: %w", err)
	}
	hr.Header.Set("Authorization", "Bearer "+e.token)
	hr.Header.Set("Content-Type", "application/x-protobuf")
	resp, err := e.httpc.Do(hr)
	if err != nil {
		return fmt.Errorf("post traces: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return fmt.Errorf("traces relay %d: %s", resp.StatusCode, msg)
	}
	return nil
}

// Str and Int build attributes.
func Str(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}

func Int(k string, v int64) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: v}}}
}

func Bool(k string, v bool) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: v}}}
}

// CheckTracer turns check runs into spans while the Console's traces gate
// has check traces on.
type CheckTracer struct {
	exp      *Exporter
	resource *resourcepb.Resource
	on       atomic.Bool
	// OnStart sees each run's trace ID, so the OBI pipeline keeps the
	// target's spans of that trace.
	OnStart func(id [16]byte)
}

// NewCheckTracer: host is this agent's host name (statusharbor.host).
func NewCheckTracer(exp *Exporter, host string) *CheckTracer {
	return &CheckTracer{exp: exp, resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
		Str("service.name", CheckService),
		Str("statusharbor.host", host),
	}}}
}

// SetEnabled follows the gate.
func (c *CheckTracer) SetEnabled(on bool) {
	if c != nil {
		c.on.Store(on)
	}
}

// Start returns a trace for the run, nil when check traces are off.
func (c *CheckTracer) Start(sendHeader bool) *checks.Trace {
	if c == nil || !c.on.Load() {
		return nil
	}
	tr := checks.NewTrace(sendHeader)
	if c.OnStart != nil {
		c.OnStart(tr.TraceID)
	}
	return tr
}

// Run is one finished check run.
type Run struct {
	CheckID, CheckType, Name string
	Start, End               time.Time
	Up                       bool
	StatusCode               int
}

// Finish queues the run's spans. Nil trace is a no-op.
func (c *CheckTracer) Finish(tr *checks.Trace, r Run) {
	if c == nil || tr == nil {
		return
	}
	c.exp.Add(c.resource, CheckSpans(tr, r)...)
}

// CheckSpans is the root span and one child per phase. The root carries
// the phase durations as attributes so lists can show the breakdown
// without the whole trace. A down run's root has status error (no
// message: errors can quote the target URL).
func CheckSpans(tr *checks.Trace, r Run) []*tracepb.Span {
	root := &tracepb.Span{
		TraceId:           tr.TraceID[:],
		SpanId:            tr.SpanID[:],
		Name:              "check " + r.Name,
		Kind:              tracepb.Span_SPAN_KIND_CLIENT,
		StartTimeUnixNano: uint64(r.Start.UnixNano()),
		EndTimeUnixNano:   uint64(r.End.UnixNano()),
		Attributes: []*commonpb.KeyValue{
			Str("statusharbor.check_id", r.CheckID),
			Str("statusharbor.check_type", r.CheckType),
			Bool("statusharbor.check_up", r.Up),
		},
		Status: &tracepb.Status{Code: tracepb.Status_STATUS_CODE_OK},
	}
	if !r.Up {
		root.Status.Code = tracepb.Status_STATUS_CODE_ERROR
	}
	if r.StatusCode > 0 {
		root.Attributes = append(root.Attributes, Int("http.response.status_code", int64(r.StatusCode)))
	}
	spans := []*tracepb.Span{root}
	for _, p := range tr.Phases {
		switch p.Name {
		case "dns", "connect", "tls":
			root.Attributes = append(root.Attributes, Int("statusharbor."+p.Name+"_ms", p.End.Sub(p.Start).Milliseconds()))
		case "request":
			root.Attributes = append(root.Attributes, Int("statusharbor.ttfb_ms", p.End.Sub(p.Start).Milliseconds()))
		}
		id := make([]byte, 8)
		_, _ = rand.Read(id)
		spans = append(spans, &tracepb.Span{
			TraceId:           tr.TraceID[:],
			SpanId:            id,
			ParentSpanId:      tr.SpanID[:],
			Name:              p.Name,
			Kind:              tracepb.Span_SPAN_KIND_INTERNAL,
			StartTimeUnixNano: uint64(p.Start.UnixNano()),
			EndTimeUnixNano:   uint64(p.End.UnixNano()),
		})
	}
	return spans
}
