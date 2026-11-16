package agent

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf"
	"github.com/statusharbor/lighthouse/internal/transport"
)

type fakeEBPF struct {
	mu       sync.Mutex
	statuses []ebpf.Status
	applied  [][]string
}

func (f *fakeEBPF) Apply(enabled []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, enabled)
}

func (f *fakeEBPF) Statuses() []ebpf.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ebpf.Status(nil), f.statuses...)
}

func (f *fakeEBPF) set(s ...ebpf.Status) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses = s
}

// The status report rides a heartbeat when it changed and until a
// heartbeat carrying it succeeds.
func TestSendHeartbeat_EBPFStatusOnChange(t *testing.T) {
	var (
		mu   sync.Mutex
		seen [][]transport.EBPFStatus
		fail bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req transport.HeartbeatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		seen = append(seen, req.EBPFStatus)
		f := fail
		mu.Unlock()
		if f {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(transport.HeartbeatResponse{ConfigEtag: "e"})
	}))
	t.Cleanup(srv.Close)
	r := NewRunner(&Config{Token: "lh_test"}, transport.NewClient(srv.URL, "lh_test", ""), &fakeExecutor{}, "", "")
	fe := &fakeEBPF{}
	r.SetEBPF(fe)
	ctx := context.Background()
	beat := func(wantErr bool) {
		t.Helper()
		if _, err := r.SendHeartbeat(ctx); (err != nil) != wantErr {
			t.Fatalf("heartbeat err=%v, wantErr=%v", err, wantErr)
		}
	}

	off := ebpf.Status{Collector: "hello", State: ebpf.StateDisabled, Reason: ebpf.ReasonRemoteOff}
	on := ebpf.Status{Collector: "hello", State: ebpf.StateRunning}
	fe.set(off)
	beat(false) // 0: first report
	beat(false) // 1: unchanged, omitted
	fe.set(on)
	mu.Lock()
	fail = true
	mu.Unlock()
	beat(true) // 2: changed, but the heartbeat fails
	mu.Lock()
	fail = false
	mu.Unlock()
	beat(false) // 3: resent
	beat(false) // 4: acked, omitted

	wantOff := []transport.EBPFStatus{{Collector: "hello", State: "disabled", Reason: "remote_off"}}
	wantOn := []transport.EBPFStatus{{Collector: "hello", State: "running"}}
	mu.Lock()
	defer mu.Unlock()
	if want := [][]transport.EBPFStatus{wantOff, nil, wantOn, wantOn, nil}; !reflect.DeepEqual(seen, want) {
		t.Fatalf("ebpf_status per heartbeat:\n got %v\nwant %v", seen, want)
	}
}

func TestApplyEBPFGate(t *testing.T) {
	r := NewRunner(&Config{Token: "lh_test"}, nil, &fakeExecutor{}, "", "")
	r.ApplyEBPFGate(&transport.EBPFGate{Collectors: []string{"hello"}}) // no manager: no-op
	fe := &fakeEBPF{}
	r.SetEBPF(fe)
	r.ApplyEBPFGate(&transport.EBPFGate{Collectors: []string{"hello"}})
	r.ApplyEBPFGate(nil)
	if want := [][]string{{"hello"}, nil}; !reflect.DeepEqual(fe.applied, want) {
		t.Fatalf("applied: got %v, want %v", fe.applied, want)
	}
}

func TestEBPFSink(t *testing.T) {
	var (
		mu   sync.Mutex
		sent []transport.EBPFEnvelope
	)
	b := ebpf.NewBatcher(func(_ context.Context, ev []transport.EBPFEnvelope) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, ev...)
		return nil
	}, 1<<20, 1, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.Run(ctx); close(done) }()

	s := newEBPFSink("node-1", "boot-1", b)
	c := s.forCollector("hello")
	c.Gauge("lighthouse_l7_requests_per_second", 1, map[string]string{"kind": "http", "service": "s"})
	c.Gauge("lighthouse_l7_requests_per_second", 2, map[string]string{"service": "s", "kind": "http"}) // same series, other map order
	c.Gauge("lighthouse_l7_requests_per_second", 3, map[string]string{"kind": "grpc"})
	s.gauges["stale"] = transport.HostSample{Name: "g", Value: 4, Timestamp: time.Now().Add(-gaugeTTL - time.Second).UnixMilli()}
	at := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	c.Event("oom_kill", at, map[string]int{"pid": 42})
	c.Event("bad", at, func() {}) // not encodable: counted, not sent
	cancel()
	<-done

	got, _ := s.Collect()
	vals := map[float64]bool{}
	self := map[string]float64{}
	for _, g := range got {
		if strings.HasPrefix(g.Name, "lighthouse_ebpf_events_") || strings.HasPrefix(g.Name, "lighthouse_ebpf_series_") {
			self[g.Name] = g.Value
			continue
		}
		vals[g.Value] = true
	}
	if !reflect.DeepEqual(vals, map[float64]bool{2: true, 3: true}) {
		t.Errorf("gauges: got %v, want latest per series {2,3} and the stale one dropped", vals)
	}
	if self["lighthouse_ebpf_events_encode_errors_total"] != 1 || self["lighthouse_ebpf_events_dropped_total"] != 0 {
		t.Errorf("self metrics: %v", self)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 1 {
		t.Fatalf("sent %d events, want 1", len(sent))
	}
	e := sent[0]
	if e.Schema != ebpf.SchemaVersion || e.HostID != "node-1" || e.BootID != "boot-1" || e.Collector != "hello" ||
		e.Kind != "oom_kill" || !e.Time.Equal(at) || string(e.Payload) != `{"pid":42}` || e.Seq == 0 {
		t.Fatalf("envelope: %+v", e)
	}
}

func TestLoad_EBPFKillSwitch(t *testing.T) {
	t.Setenv(EnvToken, "lh_x")
	t.Setenv(EnvEBPF, "off")
	cfg, err := Load(strings.NewReader(""))
	if err != nil || cfg.Agent.EBPF != "off" {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
	t.Setenv(EnvEBPF, "of")
	if _, err := Load(strings.NewReader("")); err == nil || !strings.Contains(err.Error(), "agent.ebpf") {
		t.Fatalf("typo in kill switch must fail, got %v", err)
	}
}

// Plan 07 daily quotas: events and new series past the day's quota are
// dropped and counted; series already known keep updating; a new day
// starts fresh.
func TestEBPFSink_DailyQuotas(t *testing.T) {
	defer ebpf.SetQuotas(nil)
	ebpf.SetQuotas(&ebpf.Quotas{EventsPerDay: 2, NewSeriesPerDay: 2})
	b := ebpf.NewBatcher(func(context.Context, []transport.EBPFEnvelope) error { return nil }, 1<<20, 100, time.Hour)
	s := newEBPFSink("node-1", "boot-1", b)
	c := s.forCollector("incident")
	for i := range 3 {
		c.Event("oom_kill", time.Now(), map[string]int{"pid": i})
		c.Gauge("lighthouse_top_cpu_cores", float64(i), map[string]string{"group": strconv.Itoa(i)})
	}
	c.Gauge("lighthouse_top_cpu_cores", 9, map[string]string{"group": "0"}) // known series still updates
	got, _ := s.Collect()
	vals := map[string]float64{}
	for _, g := range got {
		vals[g.Name+"|"+g.Labels["group"]] = g.Value
	}
	if vals["lighthouse_top_cpu_cores|0"] != 9 || vals["lighthouse_top_cpu_cores|1"] != 1 || len(s.gauges) != 2 {
		t.Errorf("gauges: %v", vals)
	}
	if vals["lighthouse_ebpf_events_quota_dropped_total|"] != 1 || vals["lighthouse_ebpf_series_quota_dropped_total|"] != 1 {
		t.Errorf("drop counters: %v", vals)
	}
	if b.Dropped() != 0 && s.eventsToday != 2 {
		t.Errorf("events admitted: %d", s.eventsToday)
	}

	s.mu.Lock()
	s.rollDay(time.Now().Add(24 * time.Hour))
	s.mu.Unlock()
	c.Gauge("lighthouse_top_cpu_cores", 1, map[string]string{"group": "new"})
	if _, ok := s.gauges["lighthouse_top_cpu_cores\x00group=new"]; !ok {
		t.Error("new day did not admit a new series")
	}
}

// Plan 09 acceptance criterion 2: nothing outside the allow-list leaves
// the agent. Unknown series and label keys are dropped and counted;
// unknown event fields are stripped; unknown event kinds are dropped.
func TestEBPFSink_Allowlist(t *testing.T) {
	var (
		mu   sync.Mutex
		sent []transport.EBPFEnvelope
	)
	b := ebpf.NewBatcher(func(_ context.Context, ev []transport.EBPFEnvelope) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, ev...)
		return nil
	}, 1<<20, 1, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.Run(ctx); close(done) }()

	s := newEBPFSink("node-1", "boot-1", b)
	c := s.forCollector("incident")
	c.Gauge("lighthouse_secret_total", 1, nil)                                              // unknown name
	c.Gauge("lighthouse_top_cpu_cores", 1, map[string]string{"group": "g", "cmdline": "x"}) // unknown label key
	c.Gauge("lighthouse_top_cpu_cores", 2, map[string]string{"group": "g"})                 // allowed
	c.Event("oom_kill", time.Now(), map[string]any{"pid": 1, "comm": "pg", "environ": "PASSWORD=x"})
	c.Event("keystroke", time.Now(), map[string]any{"key": "a"})
	cancel()
	<-done

	got, _ := s.Collect()
	var notAllowed float64
	series := 0
	for _, g := range got {
		switch g.Name {
		case "lighthouse_ebpf_series_not_allowed_total":
			notAllowed = g.Value
		case "lighthouse_top_cpu_cores":
			series++
		}
	}
	if series != 1 || notAllowed != 3 {
		t.Fatalf("series kept %d, not allowed %v", series, notAllowed)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 1 || strings.Contains(string(sent[0].Payload), "environ") || !strings.Contains(string(sent[0].Payload), `"comm":"pg"`) {
		t.Fatalf("events sent: %+v", sent)
	}
}

// Every eBPF series name written in the agent's source is on the
// allow-list, so a new series fails here rather than being dropped in
// production.
func TestEBPFAllowlist_CoversSource(t *testing.T) {
	re := regexp.MustCompile(`"(lighthouse_(?:ebpf|top|l7)_[a-z0-9_]+[a-z0-9])"`)
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			if _, ok := allowlist.Series[m[1]]; !ok && !strings.HasSuffix(m[1], "_") {
				t.Errorf("%s: series %s is not on the allow-list (ebpf_allowlist.json)", path, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
