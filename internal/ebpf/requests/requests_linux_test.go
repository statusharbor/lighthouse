//go:build linux

package requests

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/traces"
)

type recSink struct {
	mu     sync.Mutex
	gauges map[string]float64
}

func (s *recSink) Gauge(name string, v float64, l map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gauges == nil {
		s.gauges = map[string]float64{}
	}
	if l["service"] != "comm:spike:8080" {
		return // other services OBI sees on the test host
	}
	s.gauges[name+"|"+l["kind"]+"|"+l["route"]+"|"+l["quantile"]] = v
}
func (*recSink) Event(string, time.Time, any) {}

// Against a real OBI (REQUESTS_TEST_METRICS_URL, with the outer script
// sending load: 70% /ok, 20% /fail, 10% /users/<id>): the collector turns
// OBI's output into rate, error share and latency per route.
func TestRequests_OBI(t *testing.T) {
	url := os.Getenv("REQUESTS_TEST_METRICS_URL")
	if url == "" {
		t.Skip("set REQUESTS_TEST_METRICS_URL to an OBI Prometheus endpoint")
	}
	c := New(nil, "", url, "")
	c.Interval = 3 * time.Second
	sink := &recSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, sink) }()
	time.Sleep(20 * time.Second)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	t.Logf("gauges: %v", sink.gauges)
	if sink.gauges["lighthouse_l7_requests_per_second|http|/ok|"] <= 0 {
		t.Error("no /ok rate")
	}
	if sink.gauges["lighthouse_l7_server_error_ratio|http|/fail|"] != 1 {
		t.Error("/fail not all server errors")
	}
	if _, ok := sink.gauges["lighthouse_l7_requests_per_second|http|/users/{id}|"]; !ok {
		t.Error("/users/{id} route missing")
	}
	if p95 := sink.gauges["lighthouse_l7_latency_ms|http|/ok|0.95"]; p95 < 9 || p95 > 60 {
		t.Errorf("/ok p95 = %v ms, want about 10-25", p95)
	}
}

// TRC-U-F6: a supervised OBI never gets context propagation, whether
// traces are on or off; the trace export appears only while they are on.
func TestOBIEnv_PropagationAlwaysOff(t *testing.T) {
	p := traces.NewPipeline(traces.NewExporter("http://unused", "t", http.DefaultClient), "h", 5)
	p.Token = "tok"
	for _, on := range []bool{false, true} {
		p.SetGate(on, 5, 100)
		env := strings.Join(obiEnv([]string{"OTEL_EBPF_BPF_CONTEXT_PROPAGATION=all"}, "80", p), "\n")
		// The last assignment wins in exec's environment.
		last := env[strings.LastIndex(env, "OTEL_EBPF_BPF_CONTEXT_PROPAGATION="):]
		if !strings.HasPrefix(last, "OTEL_EBPF_BPF_CONTEXT_PROPAGATION=disabled") {
			t.Fatalf("on=%v: propagation not disabled last: %s", on, last)
		}
		if got := strings.Contains(env, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:19401/v1/traces"); got != on {
			t.Fatalf("on=%v: trace export present=%v", on, got)
		}
		if on && !strings.Contains(env, "OTEL_EXPORTER_OTLP_TRACES_HEADERS=X-Lighthouse-Traces-Token=tok") {
			t.Fatal("token missing")
		}
	}
}

// Pin directories of agents that are gone are removed; a live agent's and
// anything not ours are kept.
func TestSweepPins_RemovesDeadAgentsOnly(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"statusharbor-obi-100", "statusharbor-obi-200", "statusharbor-obi-x", "otel"} {
		if err := os.MkdirAll(filepath.Join(root, d, "otel"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sweepPins(root, func(pid int) bool { return pid == 200 })
	entries, _ := os.ReadDir(root)
	var left []string
	for _, e := range entries {
		left = append(left, e.Name())
	}
	if got := strings.Join(left, ","); got != "otel,statusharbor-obi-200,statusharbor-obi-x" {
		t.Fatalf("left %s", got)
	}
	if !processAlive(os.Getpid()) || processAlive(1<<30) {
		t.Fatal("processAlive")
	}
}
