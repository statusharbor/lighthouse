package traces

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/statusharbor/lighthouse/internal/checks"
)

func TestCheckSpans_RootAndPhases(t *testing.T) {
	tr := checks.NewTrace(true)
	t0 := time.Now()
	tr.Phases = []checks.Phase{
		{Name: "dns", Start: t0, End: t0.Add(12 * time.Millisecond)},
		{Name: "request", Start: t0.Add(12 * time.Millisecond), End: t0.Add(40 * time.Millisecond)},
	}
	spans := CheckSpans(tr, Run{CheckID: "c1", CheckType: "https", Name: "api", Start: t0, End: t0.Add(50 * time.Millisecond), StatusCode: 503})
	if len(spans) != 3 {
		t.Fatalf("spans = %d", len(spans))
	}
	root := spans[0]
	if root.Name != "check api" || root.Status.Code != tracepb.Status_STATUS_CODE_ERROR || len(root.ParentSpanId) != 0 {
		t.Fatalf("root = %v", root)
	}
	attrs := map[string]string{}
	for _, a := range root.Attributes {
		attrs[a.Key] = a.Value.String()
	}
	for _, k := range []string{"statusharbor.check_id", "statusharbor.dns_ms", "statusharbor.ttfb_ms", "http.response.status_code", "statusharbor.check_up"} {
		if _, ok := attrs[k]; !ok {
			t.Fatalf("root lacks %s: %v", k, attrs)
		}
	}
	for _, c := range spans[1:] {
		if string(c.ParentSpanId) != string(root.SpanId) || string(c.TraceId) != string(root.TraceId) {
			t.Fatalf("child %s not under the root", c.Name)
		}
	}
}

// A refused batch waits for the next flush; nothing is lost.
func TestExporter_RetriesRefusedBatch(t *testing.T) {
	var refuse atomic.Bool
	refuse.Store(true)
	var got atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != Path || r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("request %s %s", r.URL.Path, r.Header.Get("Authorization"))
		}
		if refuse.Load() {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var td tracepb.TracesData
		if err := proto.Unmarshal(body, &td); err != nil {
			t.Error(err)
		}
		for _, rs := range td.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				got.Add(int64(len(ss.Spans)))
			}
		}
	}))
	defer srv.Close()

	exp := NewExporter(srv.URL, "tok", srv.Client())
	tracer := NewCheckTracer(exp, "web-1")
	if tracer.Start(true) != nil {
		t.Fatal("off until the gate says so")
	}
	tracer.SetEnabled(true)
	tr := tracer.Start(true)
	tracer.Finish(tr, Run{CheckID: "c1", Name: "api", Start: time.Now(), End: time.Now(), Up: true})

	exp.Flush(context.Background())
	if got.Load() != 0 {
		t.Fatal("refused batch counted as sent")
	}
	refuse.Store(false)
	exp.Flush(context.Background())
	if got.Load() != 1 {
		t.Fatalf("sent %d spans after retry, want 1", got.Load())
	}
}
