package ebpf

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var capable = Host{BTF: true, Capabilities: []string{"CAP_BPF", "CAP_PERFMON"}, Lockdown: "none"}

type fakeCollector struct {
	name string
	req  Requirements
	runs atomic.Int32
	// run is called per Run; nil blocks until ctx is cancelled.
	run func(ctx context.Context) error
}

func (f *fakeCollector) Name() string               { return f.name }
func (f *fakeCollector) Requirements() Requirements { return f.req }
func (f *fakeCollector) Run(ctx context.Context, _ Sink) error {
	f.runs.Add(1)
	if f.run != nil {
		return f.run(ctx)
	}
	<-ctx.Done()
	return nil
}

type nopSink struct{}

func (nopSink) Gauge(string, float64, map[string]string) {}
func (nopSink) Event(string, time.Time, any)             {}

func fastManager(t *testing.T, cs []Collector, h Host, kill bool) *Manager {
	t.Helper()
	m := NewManager(context.Background(), cs, h, kill, func(string) Sink { return nopSink{} })
	m.baseDelay, m.maxDelay, m.maxAttempts = time.Millisecond, 4*time.Millisecond, 3
	t.Cleanup(m.Stop)
	return m
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func stateOf(m *Manager, name string) Status {
	for _, s := range m.Statuses() {
		if s.Collector == name {
			return s
		}
	}
	return Status{}
}

func TestCheck(t *testing.T) {
	cases := []struct {
		name string
		req  Requirements
		host Host
		want Reason
	}{
		{"FND-U-P1 all positive", Requirements{BTF: true, KernelMemory: true}, capable, ""},
		{"CAP_SYS_ADMIN instead of BPF+PERFMON", Requirements{}, Host{Capabilities: []string{"CAP_SYS_ADMIN"}}, ""},
		{"FND-U-F1 no BTF", Requirements{BTF: true}, Host{Capabilities: capable.Capabilities}, ReasonNoBTF},
		{"BTF not required", Requirements{}, Host{Capabilities: capable.Capabilities}, ""},
		{"only CAP_BPF", Requirements{}, Host{Capabilities: []string{"CAP_BPF"}}, ReasonMissingCapability},
		{"no capabilities", Requirements{}, Host{BTF: true}, ReasonMissingCapability},
		{"FND-U-F2 lockdown confidentiality", Requirements{KernelMemory: true}, Host{BTF: true, Capabilities: capable.Capabilities, Lockdown: "confidentiality"}, ReasonLockdown},
		{"lockdown integrity is fine", Requirements{KernelMemory: true}, Host{Capabilities: capable.Capabilities, Lockdown: "integrity"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := Check(tc.req, tc.host); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParsers(t *testing.T) {
	// CAP_NET_ADMIN(12) | CAP_SYS_PTRACE(19) | CAP_PERFMON(38) | CAP_BPF(39), plus an unknown bit 43.
	got := CapabilitiesFromStatus("CapInh:\t0\nCapEff:\t000008c000081000\n")
	want := []string{"CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_PERFMON", "CAP_BPF", "CAP_43"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("capabilities: got %v, want %v", got, want)
	}
	for in, want := range map[string][]string{"CapEff:\tzz\n": {}, "Name:\tx\n": {}} {
		if got := CapabilitiesFromStatus(in); !reflect.DeepEqual(got, want) {
			t.Errorf("capabilities(%q): got %v, want %v", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"none [integrity] confidentiality\n": "integrity",
		"[none] integrity confidentiality\n": "none",
		"":                                   "",
	} {
		if got := LockdownMode(in); got != want {
			t.Errorf("lockdown(%q): got %q, want %q", in, got, want)
		}
	}
}

// FND-U-F3 plus "kill switch loads nothing": no probe and no Run.
func TestManager_KillSwitchWins(t *testing.T) {
	probed := false
	c := &fakeCollector{name: "a", req: Requirements{Features: []Feature{{Name: "x", Probe: func() error { probed = true; return nil }}}}}
	m := fastManager(t, []Collector{c}, capable, true)
	m.Apply([]string{"a"})
	if s := stateOf(m, "a"); s.State != StateDisabled || s.Reason != ReasonKillSwitch {
		t.Fatalf("status: %+v", s)
	}
	if probed || c.runs.Load() != 0 {
		t.Fatalf("kill switch on but probed=%v runs=%d", probed, c.runs.Load())
	}
}

func TestManager_Planning(t *testing.T) {
	ok := &fakeCollector{name: "ok"}
	noBTF := &fakeCollector{name: "btf", req: Requirements{BTF: true}}
	noFeat := &fakeCollector{name: "feat", req: Requirements{Features: []Feature{{Name: "ringbuf", Probe: func() error { return errors.New("not supported") }}}}}
	m := fastManager(t, []Collector{ok, noBTF, noFeat}, Host{Capabilities: capable.Capabilities}, false)

	want := []Status{
		{Collector: "ok", State: StateDisabled, Reason: ReasonRemoteOff},
		{Collector: "btf", State: StateUnsupported, Reason: ReasonNoBTF, Detail: "/sys/kernel/btf/vmlinux not found"},
		{Collector: "feat", State: StateUnsupported, Reason: ReasonMissingFeature, Detail: "ringbuf: not supported"},
	}
	if got := m.Statuses(); !reflect.DeepEqual(got, want) {
		t.Fatalf("before Apply:\n got %+v\nwant %+v", got, want)
	}
	m.Apply([]string{"ok", "btf", "feat"})
	waitFor(t, "ok running", func() bool { return ok.runs.Load() == 1 })
	if noBTF.runs.Load()+noFeat.runs.Load() != 0 {
		t.Fatal("unsupported collector was run")
	}
	if s := stateOf(m, "ok"); s.State != StateRunning {
		t.Fatalf("ok: %+v", s)
	}
}

// FND-U-P6 and FND-U-F6 (retry limit): restarts with backoff, then failed.
func TestManager_RestartsThenFails(t *testing.T) {
	var mu sync.Mutex
	var at []time.Time
	c := &fakeCollector{name: "flaky", run: func(context.Context) error {
		mu.Lock()
		at = append(at, time.Now())
		mu.Unlock()
		return errors.New("attach failed")
	}}
	m := fastManager(t, []Collector{c}, capable, false)
	m.Apply([]string{"flaky"})
	waitFor(t, "failed", func() bool { return stateOf(m, "flaky").State == StateFailed })

	s := stateOf(m, "flaky")
	if s.Reason != ReasonLoadFailed || s.Detail != "attach failed" {
		t.Fatalf("status: %+v", s)
	}
	time.Sleep(20 * time.Millisecond)
	if n := c.runs.Load(); n != 3 {
		t.Fatalf("runs: got %d, want maxAttempts=3", n)
	}
	mu.Lock()
	defer mu.Unlock()
	// baseDelay=1ms doubles: at least 1ms, then at least 2ms.
	if d1, d2 := at[1].Sub(at[0]), at[2].Sub(at[1]); d1 < time.Millisecond || d2 < 2*time.Millisecond {
		t.Fatalf("delays should be >= 1ms then >= 2ms: %v then %v", d1, d2)
	}
}

// A panic is a failure like any other and does not take down the others.
func TestManager_PanicIsolated(t *testing.T) {
	bad := &fakeCollector{name: "bad", run: func(context.Context) error { panic("boom") }}
	good := &fakeCollector{name: "good"}
	m := fastManager(t, []Collector{bad, good}, capable, false)
	m.Apply([]string{"bad", "good"})
	waitFor(t, "bad failed", func() bool { return stateOf(m, "bad").State == StateFailed })
	if s := stateOf(m, "bad"); s.Detail != "panic: boom" {
		t.Fatalf("bad: %+v", s)
	}
	if s := stateOf(m, "good"); s.State != StateRunning || good.runs.Load() != 1 {
		t.Fatalf("good affected: %+v runs=%d", s, good.runs.Load())
	}
}

// FND-U-P7 and FND-U-F6 (stopped on purpose): a flag change touches only
// the named collector, and a stopped collector is not restarted.
func TestManager_RemoteFlags(t *testing.T) {
	a, b := &fakeCollector{name: "a"}, &fakeCollector{name: "b"}
	m := fastManager(t, []Collector{a, b}, capable, false)
	m.Apply([]string{"a", "b"})
	waitFor(t, "both running", func() bool { return a.runs.Load() == 1 && b.runs.Load() == 1 })

	m.Apply([]string{"b"})
	if s := stateOf(m, "a"); s.State != StateDisabled || s.Reason != ReasonRemoteOff {
		t.Fatalf("a after off: %+v", s)
	}
	time.Sleep(20 * time.Millisecond)
	if a.runs.Load() != 1 || b.runs.Load() != 1 {
		t.Fatalf("runs after stopping a: a=%d b=%d, want 1 and 1", a.runs.Load(), b.runs.Load())
	}

	m.Apply([]string{"a", "b"})
	waitFor(t, "a restarted", func() bool { return a.runs.Load() == 2 })
	if b.runs.Load() != 1 {
		t.Fatalf("b restarted by a's flag: runs=%d", b.runs.Load())
	}
	m.Apply(nil)
	for _, s := range m.Statuses() {
		if s.State != StateDisabled {
			t.Fatalf("feature off but %+v", s)
		}
	}
}

// Switching a failed collector off and on retries it.
func TestManager_FailedRetriedAfterToggle(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	c := &fakeCollector{name: "c", run: func(ctx context.Context) error {
		if fail.Load() {
			return errors.New("nope")
		}
		<-ctx.Done()
		return nil
	}}
	m := fastManager(t, []Collector{c}, capable, false)
	m.Apply([]string{"c"})
	waitFor(t, "failed", func() bool { return stateOf(m, "c").State == StateFailed })
	m.Apply([]string{"c"})
	if stateOf(m, "c").State != StateFailed {
		t.Fatal("failed collector restarted while still enabled")
	}
	fail.Store(false)
	m.Apply(nil)
	m.Apply([]string{"c"})
	waitFor(t, "running again", func() bool { return stateOf(m, "c").State == StateRunning && c.runs.Load() == 4 })
}

type degradingCollector struct{ fakeCollector }

func (d *degradingCollector) Run(ctx context.Context, s Sink) error {
	s.(Degrader).Degrade("no socket iterator: close-time data only")
	<-ctx.Done()
	return nil
}

// A collector running without part of its kernel support reports
// degraded with the reason, and keeps running (criterion 8 of plan 04).
func TestManager_CollectorDegrades(t *testing.T) {
	c := &degradingCollector{fakeCollector{name: "network"}}
	m := fastManager(t, []Collector{c}, capable, false)
	m.Apply([]string{"network"})
	waitFor(t, "degraded", func() bool { return stateOf(m, "network").State == StateDegraded })
	if s := stateOf(m, "network"); s.Reason != ReasonPartial || s.Detail != "no socket iterator: close-time data only" {
		t.Fatalf("status: %+v", s)
	}
}
