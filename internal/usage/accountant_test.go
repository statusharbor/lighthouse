package usage

import (
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf/identity"
)

var t0 = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func k(pid uint32, start uint64) identity.Key { return identity.Key{PID: pid, StartTicks: start} }

func TestGroup(t *testing.T) {
	cases := map[string]struct {
		p      identity.Process
		comm   string
		kernel bool
	}{
		"pod:db/pg-0":            {identity.Process{Pod: "pg-0", Namespace: "db", ContainerID: "abc"}, "postgres", false},
		"container:0123456789ab": {identity.Process{ContainerID: "0123456789abcdef"}, "nginx", false}, // PRC-U-P3, F8
		"unit:cron.service":      {identity.Process{Unit: "cron.service"}, "cron", false},
		"kernel:kworker":         {identity.Process{}, "kworker/3:2", true},
		"process:bash":           {identity.Process{}, "bash", false},
	}
	for want, c := range cases {
		if got := Group(c.p, c.comm, c.kernel); got != want {
			t.Errorf("Group(%+v, %q) = %q, want %q", c.p, c.comm, got, want)
		}
	}
}

func TestAccountant(t *testing.T) {
	a := NewAccountant()
	// First poll: baseline only, even for processes with large totals.
	if _, ok := a.Poll([]Proc{{Key: k(10, 1), Group: "pod:web/api", CPUNS: 500e9, RSS: 100}}, t0); ok {
		t.Fatal("first poll produced an interval")
	}

	// 10 s later: api used 5 s of CPU (0.5 cores); a new process started and
	// used 2 s; a short process came and went between polls (exit event
	// only, 1 s); api's thread exits are dropped (the poll covers them).
	a.AddExit(k(20, 5), 1e9, "container:aaaaaaaaaaaa")
	a.AddExit(k(10, 1), 3e9, "pod:web/api")
	a.AddFileIO("pod:web/api", 10_000)
	a.AddNetwork("pod:web/api", 50_000)
	iv, ok := a.Poll([]Proc{
		{Key: k(10, 1), Group: "pod:web/api", CPUNS: 505e9, RSS: 200},
		{Key: k(11, 9), Group: "unit:cron.service", CPUNS: 2e9, RSS: 50},
	}, t0.Add(10*time.Second))
	if !ok {
		t.Fatal("no interval")
	}
	// PRC-U-P2.
	want := map[string]float64{"pod:web/api": 0.5, "unit:cron.service": 0.2, "container:aaaaaaaaaaaa": 0.1}
	for g, v := range want {
		if iv.CPU[g] < v-1e-9 || iv.CPU[g] > v+1e-9 {
			t.Errorf("CPU %s = %v, want %v", g, iv.CPU[g], v)
		}
	}
	if iv.Memory["pod:web/api"] != 200 || iv.FileIO["pod:web/api"] != 1000 || iv.Network["pod:web/api"] != 5000 {
		t.Errorf("interval: %+v", iv)
	}

	// PRC-U-F1: cron exits; the poll saw 2 s, the exit event says 2.5 s:
	// only 0.5 s is added. PRC-U-F6: a new process with cron's pid but
	// another start time is a new process.
	a.AddExit(k(11, 9), 2.5e9, "unit:cron.service")
	iv, _ = a.Poll([]Proc{
		{Key: k(10, 1), Group: "pod:web/api", CPUNS: 505e9},
		{Key: k(11, 77), Group: "process:sleep", CPUNS: 1e7},
	}, t0.Add(20*time.Second))
	if iv.CPU["unit:cron.service"] < 0.05-1e-9 || iv.CPU["unit:cron.service"] > 0.05+1e-9 || iv.CPU["pod:web/api"] != 0 {
		t.Errorf("exit merge: %+v", iv.CPU)
	}
	if iv.CPU["process:sleep"] <= 0 {
		t.Errorf("reused pid lost: %+v", iv.CPU)
	}

	// PRC-U-F5: a counter lower than before (restart under the same key
	// cannot happen, but be safe) gives no negative value.
	iv, _ = a.Poll([]Proc{{Key: k(10, 1), Group: "pod:web/api", CPUNS: 1}}, t0.Add(30*time.Second))
	if iv.CPU["pod:web/api"] != 0 {
		t.Errorf("negative delta: %+v", iv.CPU)
	}
}
