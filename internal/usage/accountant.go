package usage

import (
	"strings"
	"sync"
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf/identity"
)

// Group names the unit consumers are shown as: the pod, else the container,
// else the systemd unit, else the command (kernel threads folded by their
// base name, so kworker/0:1 and kworker/3:2 are one "kernel:kworker").
func Group(p identity.Process, comm string, kernelThread bool) string {
	switch {
	case p.Pod != "":
		return "pod:" + p.Namespace + "/" + p.Pod
	case p.ContainerID != "":
		return "container:" + p.ContainerID[:min(12, len(p.ContainerID))]
	case p.Unit != "":
		return "unit:" + p.Unit
	case kernelThread:
		base, _, _ := strings.Cut(comm, "/")
		return "kernel:" + base
	}
	return "process:" + comm
}

// Proc is one polled process: identity key, group and CPU time so far.
type Proc struct {
	Key   identity.Key
	Group string
	CPUNS uint64
	RSS   uint64
}

type exited struct {
	cpuNS uint64
	group string
}

// Accountant merges per-process CPU from polls and exit events, and the
// file I/O and network bytes eBPF collectors feed in, into per-group
// totals for one interval. Safe for concurrent use.
type Accountant struct {
	mu       sync.Mutex
	polled   bool
	last     map[identity.Key]Proc
	exits    map[identity.Key]exited
	fileIO   map[string]float64
	network  map[string]float64
	lastPoll time.Time
}

func NewAccountant() *Accountant {
	return &Accountant{
		last: map[identity.Key]Proc{}, exits: map[identity.Key]exited{},
		fileIO: map[string]float64{}, network: map[string]float64{},
	}
}

// AddExit records the CPU a process used over its whole life, summed per
// thread at each thread's exit (the leader can exit before its threads).
func (a *Accountant) AddExit(k identity.Key, cpuNS uint64, group string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e := a.exits[k]
	e.cpuNS += cpuNS
	e.group = group
	a.exits[k] = e
}

// AddFileIO adds logical file bytes (regular files and block devices).
func (a *Accountant) AddFileIO(group string, bytes uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fileIO[group] += float64(bytes)
}

// AddNetwork adds TCP bytes sent and received by a group.
func (a *Accountant) AddNetwork(group string, bytes uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.network[group] += float64(bytes)
}

// Interval is one interval's usage per group.
type Interval struct {
	Elapsed time.Duration
	CPU     map[string]float64 // cores
	Memory  map[string]float64 // bytes resident now
	FileIO  map[string]float64 // bytes per second
	Network map[string]float64 // bytes per second
}

// Poll takes a process list and returns the interval since the last poll.
// The first poll only sets the baseline. A process the last poll did not
// see started since then, so all its CPU is new. A process that is gone
// adds what its exit events report beyond what the polls already counted
// (PRC-U-F1); exit events of processes still running are dropped, since
// /proc already includes their exited threads.
func (a *Accountant) Poll(procs []Proc, now time.Time) (Interval, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cur := make(map[identity.Key]Proc, len(procs))
	iv := Interval{Elapsed: now.Sub(a.lastPoll), CPU: map[string]float64{}, Memory: map[string]float64{}, FileIO: a.fileIO, Network: a.network}
	for _, p := range procs {
		cur[p.Key] = p
		iv.Memory[p.Group] += float64(p.RSS)
		prev, seen := a.last[p.Key]
		switch {
		case !a.polled:
		case !seen:
			iv.CPU[p.Group] += float64(p.CPUNS)
		case p.CPUNS > prev.CPUNS:
			iv.CPU[p.Group] += float64(p.CPUNS - prev.CPUNS)
		}
	}
	for k, e := range a.exits {
		if _, alive := cur[k]; alive || !a.polled {
			continue
		}
		prev := a.last[k].CPUNS
		if e.cpuNS > prev {
			iv.CPU[e.group] += float64(e.cpuNS - prev)
		}
	}
	first := !a.polled
	a.polled, a.last, a.lastPoll = true, cur, now
	a.exits, a.fileIO, a.network = map[identity.Key]exited{}, map[string]float64{}, map[string]float64{}
	if first || iv.Elapsed <= 0 {
		return Interval{}, false
	}
	secs := iv.Elapsed.Seconds()
	for g, ns := range iv.CPU {
		iv.CPU[g] = ns / 1e9 / secs
	}
	for _, m := range []map[string]float64{iv.FileIO, iv.Network} {
		for g, b := range m {
			m[g] = b / secs
		}
	}
	return iv, true
}
