package traces

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

var t0 = time.Unix(1_800_000_000, 0)

func traceID(n int) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[8:], uint64(n)+1)
	return b
}

// server is one OBI server span of trace n.
func server(n int, d time.Duration, attrs ...*commonpb.KeyValue) *tracepb.Span {
	return &tracepb.Span{
		TraceId: traceID(n), SpanId: []byte{1, 2, 3, 4, 5, 6, 7, byte(n)},
		Name: "GET /orders/{id}", Kind: tracepb.Span_SPAN_KIND_SERVER,
		StartTimeUnixNano: uint64(t0.UnixNano()), EndTimeUnixNano: uint64(t0.Add(d).UnixNano()),
		Attributes: attrs,
	}
}

func obiData(spans ...*tracepb.Span) *tracepb.TracesData {
	return &tracepb.TracesData{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			Str("service.name", "app"), Str("service.instance.id", "web-1:4242"), Str("host.name", "web-1"),
		}},
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: spans}},
	}}}
}

func newTestPipeline(perSecond int) (*Pipeline, *Exporter) {
	exp := NewExporter("http://unused", "tok", http.DefaultClient)
	p := NewPipeline(exp, "web-1", perSecond)
	p.Resolve = func(_ context.Context, instance, _ string) string {
		if instance == "web-1:4242" {
			return "unit:shop.service"
		}
		return ""
	}
	p.SetGate(true, perSecond, 100)
	return p, exp
}

func queued(e *Exporter) []item {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]item(nil), e.queue...)
}

// TRC-U-P3 and TRC-U-F1: allow-listed attributes stay and paths are
// templated; query text, queries, headers, caller addresses and exception
// messages never leave.
func TestFilterSpan(t *testing.T) {
	sp := server(0, time.Millisecond,
		Str("url.path", "/orders/12345"), Str("http.route", "/orders/{id}"), Int("http.response.status_code", 200),
		Str("url.query", "token=secret"), Str("url.full", "http://x/orders/1?token=secret"),
		Str("db.query.text", "SELECT * FROM users WHERE email='a@b'"), Str("http.request.header.authorization", "Bearer x"),
		Str("client.address", "203.0.113.9"), Str("network.peer.address", "203.0.113.9"),
	)
	sp.Events = []*tracepb.Span_Event{{Name: "exception", Attributes: []*commonpb.KeyValue{Str("exception.message", "password=x")}}}
	sp.Status = &tracepb.Status{Code: tracepb.Status_STATUS_CODE_ERROR, Message: "boom for user a@b"}
	sp.Name = "GET /orders/12345?token=secret"
	filterSpan(sp)

	got := map[string]string{}
	for _, kv := range sp.Attributes {
		got[kv.Key] = kv.Value.String()
	}
	if len(got) != 3 || got["url.path"] == "" || sp.Name != "GET /orders/{id}" {
		t.Fatalf("kept %v, name %q", got, sp.Name)
	}
	b, _ := proto.Marshal(sp)
	for _, leak := range []string{"12345", "secret", "a@b", "203.0.113.9", "password", "Bearer"} {
		if bytes.Contains(b, []byte(leak)) {
			t.Fatalf("%q left the host", leak)
		}
	}
	client := &tracepb.Span{Kind: tracepb.Span_SPAN_KIND_CLIENT, Attributes: []*commonpb.KeyValue{Str("network.peer.address", "10.0.0.5")}}
	filterSpan(client)
	if len(client.Attributes) != 1 {
		t.Fatal("a client span keeps its dependency's address")
	}
}

// TRC-U-P4: one 5xx trace among 1,000 fast ones is kept although the
// budget allows a small share; spans carry the host's identity.
func TestPipeline_KeepsErrorsUnderBudget(t *testing.T) {
	p, exp := newTestPipeline(1)
	for i := range 1000 {
		p.Ingest(context.Background(), obiData(server(i, time.Millisecond)), t0)
	}
	p.Ingest(context.Background(), obiData(server(1000, time.Millisecond, Int("http.response.status_code", 503))), t0)
	p.Decide(t0.Add(sampleWindow))
	c := p.Counts()
	if c["kept_error"] != 1 || c["kept_sampled"] > burstSpans || c["dropped_budget"] < 900 {
		t.Fatalf("counts %v", c)
	}
	var sawError bool
	for _, it := range queued(exp) {
		if StringAttr(it.res.Attributes, "statusharbor.service") != "unit:shop.service" || StringAttr(it.res.Attributes, "statusharbor.host") != "web-1" {
			t.Fatalf("resource %v", it.res.Attributes)
		}
		if StringAttr(it.res.Attributes, "host.name") != "" {
			t.Fatal("OBI's resource attributes are replaced")
		}
		sawError = sawError || spanFailed(it.span)
	}
	if !sawError {
		t.Fatal("the error trace is not queued")
	}
}

// TRC-U-P5: a trace slower than the service's p99 is kept, ahead of the
// ordinary traces competing for the same budget.
func TestPipeline_KeepsSlowTraces(t *testing.T) {
	p, _ := newTestPipeline(1)
	for i := range 200 {
		p.Ingest(context.Background(), obiData(server(i, 10*time.Millisecond)), t0)
	}
	p.Ingest(context.Background(), obiData(server(200, 400*time.Millisecond)), t0)
	p.Decide(t0.Add(sampleWindow))
	c := p.Counts()
	if c["kept_slow"] != 1 || c["kept_sampled"] > burstSpans-1 || c["dropped_budget"] < 150 {
		t.Fatalf("counts %v", c)
	}
}

// Acceptance criterion 5: slow traces are kept only within the budget
// (beyond the burst); errors are kept whatever the budget says.
func TestPipeline_BudgetBoundsSlowNotErrors(t *testing.T) {
	p, _ := newTestPipeline(1)
	for i := range 80 { // slower than the 1s bar a service has before its p99
		p.Ingest(context.Background(), obiData(server(i, 2*time.Second)), t0)
	}
	for i := 80; i < 90; i++ {
		p.Ingest(context.Background(), obiData(server(i, time.Millisecond, Int("http.response.status_code", 500))), t0)
	}
	p.Decide(t0.Add(sampleWindow))
	c := p.Counts()
	if c["kept_error"] != 10 || c["kept_slow"] != burstSpans-10 || c["dropped_budget"] != 80-(burstSpans-10) {
		t.Fatalf("counts %v", c)
	}
}

// TRC-U-F3: with the budget spent, check traces are still kept.
func TestPipeline_KeepsCheckTracesOverBudget(t *testing.T) {
	p, _ := newTestPipeline(1)
	p.budget.AllowN(t0.Add(sampleWindow), burstSpans)
	var id [16]byte
	copy(id[:], traceID(7))
	p.MarkCheck(id)
	p.Ingest(context.Background(), obiData(server(7, time.Millisecond)), t0)
	p.Ingest(context.Background(), obiData(server(8, time.Millisecond)), t0)
	p.Decide(t0.Add(sampleWindow))
	if c := p.Counts(); c["kept_check"] != 1 || c["dropped_budget"] != 1 {
		t.Fatalf("counts %v", c)
	}
}

// TRC-U-F7: a late span of a dropped trace stays dropped.
func TestPipeline_LateSpanFollowsDecision(t *testing.T) {
	p, exp := newTestPipeline(1)
	p.budget.AllowN(t0.Add(sampleWindow), burstSpans)
	p.Ingest(context.Background(), obiData(server(1, time.Millisecond)), t0)
	p.Decide(t0.Add(sampleWindow))
	p.Ingest(context.Background(), obiData(server(1, time.Millisecond)), t0.Add(sampleWindow+time.Second))
	if c := p.Counts(); c["dropped_late"] != 1 || len(queued(exp)) != 0 {
		t.Fatalf("counts %v, queued %d", c, len(queued(exp)))
	}
}

// The receiver needs the token and keeps nothing while traces are off.
func TestPipeline_Receiver(t *testing.T) {
	p, exp := newTestPipeline(5)
	p.Token = "s3cret"
	body, _ := proto.Marshal(obiData(server(1, time.Millisecond, Int("http.response.status_code", 500))))
	post := func(token string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/traces", bytes.NewReader(body))
		req.Header.Set(TokenHeader, token)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		return rec.Code
	}
	if post("wrong") != http.StatusUnauthorized {
		t.Fatal("token not checked")
	}
	p.SetGate(false, 0, 100)
	if post("s3cret") != http.StatusOK {
		t.Fatal("off still answers 200")
	}
	p.SetGate(true, 0, 100)
	post("s3cret")
	p.Decide(time.Now().Add(sampleWindow))
	if len(queued(exp)) != 1 {
		t.Fatalf("queued %d, want only the span sent while on", len(queued(exp)))
	}
}

// A full pending buffer drops new ordinary spans but still takes failed
// ones, so an error during a surge is not lost.
func TestPipeline_OverflowKeepsErrors(t *testing.T) {
	p, _ := newTestPipeline(5)
	spans := make([]*tracepb.Span, 0, maxPending)
	for i := range maxPending {
		spans = append(spans, server(i, time.Millisecond))
	}
	p.Ingest(context.Background(), obiData(spans...), t0)
	p.Ingest(context.Background(), obiData(server(maxPending, time.Millisecond)), t0)
	p.Ingest(context.Background(), obiData(server(maxPending+1, time.Millisecond, Int("http.response.status_code", 503))), t0)
	p.Decide(t0.Add(sampleWindow))
	if c := p.Counts(); c["dropped_overflow"] != 1 || c["kept_error"] != 1 {
		t.Fatalf("counts %v", c)
	}
}

// The sample rate keeps its share of ordinary traces, chosen by trace ID
// (so hosts agree on a cross-host trace); failed traces ignore it.
func TestPipeline_SampleRate(t *testing.T) {
	p, _ := newTestPipeline(1000)
	p.SetGate(true, 1000, 10)
	for i := range 2000 {
		p.Ingest(context.Background(), obiData(server(i, time.Millisecond)), t0)
	}
	p.Ingest(context.Background(), obiData(server(5000, time.Millisecond, Int("http.response.status_code", 500))), t0)
	p.Decide(t0.Add(sampleWindow))
	c := p.Counts()
	if c["kept_error"] != 1 {
		t.Fatalf("errors ignore the rate: %v", c)
	}
	// What the rate lets through still meets the host budget afterwards.
	if in := c["kept_sampled"] + c["dropped_budget"]; in < 120 || in > 280 { // 10% of 2000, with slack
		t.Fatalf("%d of 2000 sampled in at 10%%: %v", in, c)
	}
	if c["dropped_sample"]+c["kept_sampled"]+c["dropped_budget"] != 2000 {
		t.Fatalf("counts %v", c)
	}
	// Raising the rate only adds traces: one kept at 10% stays kept at 50%,
	// so changing the rate never splits a trace between hosts that heard
	// of the change at different heartbeats in an unexpected way.
	for i := range 1000 {
		if id := traceID(i); sampledIn(id, 10) && !sampledIn(id, 50) {
			t.Fatalf("trace %d kept at 10%% but not at 50%%", i)
		}
	}
	if id := traceID(42); !sampledIn(id, 100) || sampledIn(id, 0) {
		t.Fatal("100% keeps all and 0% none")
	}
}
