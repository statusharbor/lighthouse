package identity

import (
	"regexp"
	"sync"
	"time"
)

// Key identifies one process for its whole life: the pid plus its start
// time in USER_HZ ticks since boot, the unit /proc/<pid>/stat uses.
type Key struct {
	PID        uint32
	StartTicks uint64
}

// ticksPerSecond is USER_HZ, fixed at 100 for the kernel's user-facing
// clock_t on every architecture Lighthouse supports.
const ticksPerSecond = 100

// KeyFromBootNS builds a Key from a kernel start_boottime in nanoseconds,
// rounded down exactly like /proc/<pid>/stat does.
func KeyFromBootNS(pid uint32, startNS uint64) Key {
	return Key{PID: pid, StartTicks: startNS / (1e9 / ticksPerSecond)}
}

// Process is what the cache knows about one process. Command-line
// arguments and environment are never collected.
type Process struct {
	Comm        string
	Exe         string
	CgroupID    uint64
	ContainerID string
	Unit        string // systemd service, for processes outside containers
	PodUID      string
	Pod         string
	Namespace   string
}

type entry struct {
	p      Process
	exited time.Time // zero while running
}

// Cache maps Key to Process. Exited processes stay for grace so events
// that arrive after the exit still resolve. It holds at most max entries;
// Put on a full cache is refused (and counted) rather than evicting a
// live process.
type Cache struct {
	grace time.Duration
	max   int

	mu      sync.Mutex
	m       map[Key]*entry
	refused uint64
}

func NewCache(grace time.Duration, max int) *Cache {
	return &Cache{grace: grace, max: max, m: map[Key]*entry{}}
}

func (c *Cache) Put(k Key, p Process) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.m[k]; !ok && len(c.m) >= c.max {
		c.refused++
		return
	}
	c.m[k] = &entry{p: p}
}

// Exit marks k as exited at at; it is removed by Sweep after grace.
func (c *Cache) Exit(k Key, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok {
		e.exited = at
	}
}

func (c *Cache) Get(k Key) (Process, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok {
		return Process{}, false
	}
	return e.p, true
}

// Sweep drops entries that exited more than grace before now.
func (c *Cache) Sweep(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.m {
		if !e.exited.IsZero() && now.Sub(e.exited) > c.grace {
			delete(c.m, k)
		}
	}
}

// Stats returns the entry count and how many Puts were refused because
// the cache was full.
func (c *Cache) Stats() (entries int, refused uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m), c.refused
}

// ponytail: pod name suffixes, not owner references (the node's pod list
// carries names only). Deployment pods end in -<template hash>-<5>,
// DaemonSet and Job pods in -<5>, StatefulSet pods in -<ordinal>; all are
// stripped so restarts and rolling deploys keep one identity.
var (
	podSuffix  = regexp.MustCompile(`-[bcdfghjklmnpqrstvwxz2456789]{5}$`)
	podHash    = regexp.MustCompile(`-[bcdfghjklmnpqrstvwxz2456789]{6,10}$`)
	podOrdinal = regexp.MustCompile(`-\d+$`)
)

// Workload is a pod's name without its rollout suffixes.
func Workload(pod string) string {
	if w := podSuffix.ReplaceAllString(pod, ""); w != pod {
		return podHash.ReplaceAllString(w, "")
	}
	return podOrdinal.ReplaceAllString(pod, "")
}

// SourceID is the service identity of a process that connects out, without
// a port (a client need not listen): "k8s:ns/workload", "unit:x.service",
// "container:/exe", "exe:/exe", or "comm:name" when nothing else is known.
func SourceID(p Process, comm string) string {
	switch {
	case p.Pod != "":
		return "k8s:" + p.Namespace + "/" + Workload(p.Pod)
	case p.Unit != "":
		return "unit:" + p.Unit
	case p.ContainerID != "":
		return "container:" + p.Exe
	case p.Exe != "":
		return "exe:" + p.Exe
	}
	return "comm:" + comm
}
