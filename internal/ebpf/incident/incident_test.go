package incident

import (
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf/identity"
)

// INC-U-P2.
func TestDecodeExit(t *testing.T) {
	cases := []struct {
		code          int32
		sig, status   int
		core          bool
		class, signal string
	}{
		{0x0009, 9, 0, false, ClassKilled, "SIGKILL"},
		{0x008B, 11, 0, true, ClassCrashed, "SIGSEGV"},
		{0x0100, 0, 1, false, ClassFailed, ""},
		{0x000F, 15, 0, false, ClassTerminated, "SIGTERM"},
		{0x000D, 13, 0, false, ClassSignaled, "SIGPIPE"},
		{0x0086, 6, 0, true, ClassCrashed, "SIGABRT"},
		{0, 0, 0, false, "", ""}, // INC-U-F1
	}
	for _, tc := range cases {
		sig, core, status := DecodeExit(tc.code)
		if sig != tc.sig || core != tc.core || status != tc.status {
			t.Errorf("DecodeExit(%#x) = %d,%v,%d; want %d,%v,%d", tc.code, sig, core, status, tc.sig, tc.core, tc.status)
		}
		if got := Classify(sig, status); got != tc.class {
			t.Errorf("Classify(%#x) = %q, want %q", tc.code, got, tc.class)
		}
		if tc.signal != "" && SignalName(sig) != tc.signal {
			t.Errorf("SignalName(%d) = %q, want %q", sig, SignalName(sig), tc.signal)
		}
	}
}

func at(sec int) time.Time { return time.Date(2026, 11, 14, 12, 0, sec, 0, time.UTC) }

func exitEv(pid uint32, code int32, ppid uint32, parent string, t time.Time) rawEvent {
	return rawEvent{Type: 2, At: t, PID: pid, StartNS: 5e9, ExitCode: code, PPID: ppid, ParentComm: parent, Comm: "app"}
}

func kinds(es []emission) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.kind
	}
	return out
}

// INC-U-P1: an OOM record becomes victim, trigger and scope, enriched
// from the identity cache.
func TestProcessor_OOM(t *testing.T) {
	cache := identity.NewCache(time.Minute, 10)
	cache.Put(identity.KeyFromBootNS(42, 7e9), identity.Process{Exe: "/usr/bin/postgres", ContainerID: "c1", Pod: "db-0", Namespace: "data"})
	p := newProcessor(cache, nil)
	es := p.handle(rawEvent{Type: 1, At: at(0), PID: 42, StartNS: 7e9, Comm: "postgres", OtherPID: 99, OtherComm: "stress", MemcgOOM: true})
	if len(es) != 1 || es[0].kind != KindOOMKill {
		t.Fatalf("got %v", kinds(es))
	}
	o := es[0].payload.(OOMKill)
	if o.Comm != "postgres" || o.Pod != "db-0" || o.Scope != "cgroup" || o.TriggerComm != "stress" || o.Exe != "/usr/bin/postgres" {
		t.Fatalf("payload: %+v", o)
	}
	if es := p.handle(rawEvent{Type: 1, PID: 1, Comm: "x"}); es[0].payload.(OOMKill).Scope != "host" {
		t.Fatal("non-memcg OOM must have host scope")
	}
	// A systemd service's events carry its unit, so the Console's service
	// map can tie them to the service.
	cache.Put(identity.KeyFromBootNS(43, 7e9), identity.Process{Exe: "/usr/bin/redis-server", Unit: "redis.service"})
	if o := p.handle(rawEvent{Type: 1, At: at(0), PID: 43, StartNS: 7e9, Comm: "redis-server"})[0].payload.(OOMKill); o.Unit != "redis.service" {
		t.Fatalf("unit: %+v", o)
	}
}

// INC-U-F2 and INC-U-F4, plus "crashes and kills always count".
func TestProcessor_TrackedFilter(t *testing.T) {
	p := newProcessor(nil, nil)
	cases := []struct {
		name  string
		ev    rawEvent
		want  int
		class string
	}{
		{"grep exits 1 under a shell", exitEv(10, 0x100, 300, "bash", at(0)), 0, ""},
		{"service exits 1 under systemd", exitEv(11, 0x100, 1, "systemd", at(0)), 1, ClassFailed},
		{"container main process exits 2", exitEv(12, 0x200, 400, "containerd-shim", at(0)), 1, ClassFailed},
		{"tracked service SIGTERM is terminated, never crashed", exitEv(13, 0x0F, 1, "systemd", at(0)), 1, ClassTerminated},
		{"untracked SIGTERM is silent", exitEv(14, 0x0F, 300, "bash", at(0)), 0, ""},
		{"untracked segfault still counts", exitEv(15, 0x8B, 300, "bash", at(0)), 1, ClassCrashed},
		{"untracked SIGKILL still counts", exitEv(16, 0x09, 300, "bash", at(0)), 1, ClassKilled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.ev.Comm = tc.name // separate crash-loop keys
			es := p.handle(tc.ev)
			if len(es) != tc.want {
				t.Fatalf("got %v, want %d events", kinds(es), tc.want)
			}
			if tc.want == 1 && es[0].payload.(ProcessExit).Class != tc.class {
				t.Fatalf("class: %+v", es[0].payload)
			}
		})
	}
	// With plan 03, a listening-port owner is tracked whatever its parent.
	pl := newProcessor(nil, func(k identity.Key) bool { return k.PID == 20 })
	if es := pl.handle(exitEv(20, 0x100, 300, "bash", at(0))); len(es) != 1 {
		t.Fatalf("listener exit: %v", kinds(es))
	}
}

// INC-U-P4: the signal sender is attached when it sent the fatal signal.
func TestProcessor_Sender(t *testing.T) {
	p := newProcessor(nil, nil)
	ev := exitEv(30, 0x09, 1, "systemd", at(0))
	ev.SenderSig, ev.OtherPID, ev.OtherComm = 9, 777, "kill"
	pe := p.handle(ev)[0].payload.(ProcessExit)
	if pe.SenderPID != 777 || pe.SenderComm != "kill" || pe.Signal != "SIGKILL" {
		t.Fatalf("payload: %+v", pe)
	}
	// SIGTERM was sent, but the process died of SIGKILL: no sender claim.
	ev2 := exitEv(31, 0x09, 1, "systemd", at(0))
	ev2.Comm, ev2.SenderSig, ev2.OtherPID = "other", 15, 777
	if pe := p.handle(ev2)[0].payload.(ProcessExit); pe.SenderPID != 0 {
		t.Fatalf("sender claimed for a different signal: %+v", pe)
	}
}

// INC-U-F10: after pid reuse, the old process's exit gets the old
// identity, not the new owner's.
func TestProcessor_PidReuse(t *testing.T) {
	cache := identity.NewCache(time.Minute, 10)
	cache.Put(identity.KeyFromBootNS(50, 1e9), identity.Process{ContainerID: "old"})
	cache.Put(identity.KeyFromBootNS(50, 9e9), identity.Process{ContainerID: "new-port-owner"})
	p := newProcessor(cache, nil)
	ev := exitEv(50, 0x8B, 1, "systemd", at(0))
	ev.StartNS = 1e9
	if pe := p.handle(ev)[0].payload.(ProcessExit); pe.ContainerID != "old" {
		t.Fatalf("got container %q, want old", pe.ContainerID)
	}
}

// INC-U-P8 and criterion 6: crash loops collapse to three events and a
// summary per minute.
func TestProcessor_CrashLoop(t *testing.T) {
	p := newProcessor(nil, nil)
	var got []string
	for i := range 5 {
		got = append(got, kinds(p.handle(exitEv(uint32(60+i), 0x8B, 1, "systemd", at(i*10))))...)
	}
	got = append(got, kinds(p.flush(at(70)))...)
	want := []string{KindProcessExit, KindProcessExit, KindProcessExit, KindCrashLoop}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	s := p.flush(at(70))
	if len(s) != 0 {
		t.Fatal("summary emitted twice")
	}

	// 100 exits in one minute: at most 4 records.
	p = newProcessor(nil, nil)
	n := 0
	for i := range 100 {
		n += len(p.handle(exitEv(uint32(i), 0x8B, 1, "systemd", at(0).Add(time.Duration(i)*590*time.Millisecond))))
	}
	n += len(p.flush(at(0).Add(2 * time.Minute)))
	if n > 4 {
		t.Fatalf("100 exits in a minute produced %d records, want <= 4", n)
	}
	// Different containers are separate loops.
	p = newProcessor(identityWith(map[uint32]string{1: "a", 2: "b"}), nil)
	m := 0
	for i := range 4 {
		m += len(p.handle(withStart(exitEv(1, 0x8B, 1, "systemd", at(i))))) + len(p.handle(withStart(exitEv(2, 0x8B, 1, "systemd", at(i)))))
	}
	if m != 6 {
		t.Fatalf("two containers x 4 exits: %d immediate events, want 3 each", m)
	}
}

func identityWith(containers map[uint32]string) *identity.Cache {
	c := identity.NewCache(time.Minute, 10)
	for pid, id := range containers {
		c.Put(identity.KeyFromBootNS(pid, 5e9), identity.Process{ContainerID: id})
	}
	return c
}

func withStart(r rawEvent) rawEvent { r.StartNS = 5e9; return r }
