// Package incident collects the host events shown next to an incident
// (docs/eBPF/02-incident-context.md): OOM kills, abnormal exits with the
// fatal-signal sender, and (later) connection failures. This file holds
// the platform-neutral rules; incident_linux.go has the collector.
package incident

import (
	"strconv"
	"strings"
	"time"
)

// Event kinds in the envelope.
const (
	KindOOMKill     = "oom_kill"
	KindProcessExit = "process_exit"
	KindCrashLoop   = "crash_loop"
)

// Exit classes.
const (
	ClassCrashed    = "crashed"    // SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE, SIGSYS, SIGTRAP
	ClassKilled     = "killed"     // SIGKILL
	ClassTerminated = "terminated" // SIGTERM, low severity
	ClassSignaled   = "signaled"   // any other signal
	ClassFailed     = "failed"     // non-zero exit status
)

var signalNames = map[int]string{
	1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT",
	7: "SIGBUS", 8: "SIGFPE", 9: "SIGKILL", 10: "SIGUSR1", 11: "SIGSEGV", 12: "SIGUSR2",
	13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM", 24: "SIGXCPU", 25: "SIGXFSZ", 31: "SIGSYS",
}

// SignalName returns e.g. "SIGKILL", or "SIG<n>" for unnamed signals.
func SignalName(sig int) string {
	if n, ok := signalNames[sig]; ok {
		return n
	}
	return "SIG" + strconv.Itoa(sig)
}

// DecodeExit splits a kernel exit code: the low 7 bits are the
// terminating signal, bit 7 the core-dump flag, the next byte the exit
// status (INC-U-P2).
func DecodeExit(code int32) (signal int, coreDumped bool, status int) {
	return int(code & 0x7f), code&0x80 != 0, int(code>>8) & 0xff
}

// Classify maps a decoded exit to its class; "" for a clean exit.
func Classify(signal, status int) string {
	switch signal {
	case 0:
		if status != 0 {
			return ClassFailed
		}
		return ""
	case 4, 5, 6, 7, 8, 11, 31:
		return ClassCrashed
	case 9:
		return ClassKilled
	case 15:
		return ClassTerminated
	}
	return ClassSignaled
}

// alwaysReported are the classes worth an event for any process; the
// rest only for tracked services, so a build full of failing greps and
// tests stays silent (INC-U-F2, INC-E-F3).
func alwaysReported(class string) bool { return class == ClassCrashed || class == ClassKilled }

// trackedParent reports whether a process is a service's main process by
// its parent: pid 1 (systemd or the init of the host), a user systemd
// instance, or a container runtime shim. Processes owning a listening
// port are tracked too, once plan 03 provides that (Collector.IsListener).
//
// ponytail: parent heuristic until plan 03; an orphan reparented to pid 1
// counts as tracked.
func trackedParent(ppid uint32, parentComm string) bool {
	if ppid == 1 {
		return true
	}
	switch {
	case strings.HasPrefix(parentComm, "containerd-shim"), parentComm == "conmon",
		parentComm == "runc", parentComm == "crun", parentComm == "systemd":
		return true
	}
	return false
}

// collapser limits crash loops: per key (command and container) at most
// keep events per window; the rest are counted and reported as one
// summary when the window ends (INC-U-P8, criterion 6).
type collapser struct {
	window time.Duration
	keep   int
	loops  map[string]*loop
}

type loop struct {
	start time.Time
	n     int
	last  ProcessExit
}

func newCollapser(window time.Duration, keep int) *collapser {
	return &collapser{window: window, keep: keep, loops: map[string]*loop{}}
}

// observe records one exit at now and reports whether to emit it. A
// window that ended before now is closed first; its summary, if any, is
// returned.
func (c *collapser) observe(key string, now time.Time, ev ProcessExit) (emit bool, summary *CrashLoop) {
	l := c.loops[key]
	if l != nil && now.Sub(l.start) >= c.window {
		summary = l.summary(c.keep, c.window)
		l = nil
	}
	if l == nil {
		l = &loop{start: now}
		c.loops[key] = l
	}
	l.n++
	l.last = ev
	return l.n <= c.keep, summary
}

// flush closes windows that ended before now and returns their summaries.
func (c *collapser) flush(now time.Time) []CrashLoop {
	var out []CrashLoop
	for k, l := range c.loops {
		if now.Sub(l.start) < c.window {
			continue
		}
		if s := l.summary(c.keep, c.window); s != nil {
			out = append(out, *s)
		}
		delete(c.loops, k)
	}
	return out
}

func (l *loop) summary(keep int, window time.Duration) *CrashLoop {
	if l.n <= keep {
		return nil
	}
	ev := l.last
	return &CrashLoop{
		Comm: ev.Comm, Exe: ev.Exe, ContainerID: ev.ContainerID, Pod: ev.Pod, Namespace: ev.Namespace, Unit: ev.Unit,
		LastClass: ev.Class, Count: l.n - keep, WindowStart: l.start, WindowEnd: l.start.Add(window),
	}
}

// Payloads. Command-line arguments and environment are never included.

type OOMKill struct {
	PID         uint32 `json:"pid"`
	Comm        string `json:"comm"`
	Exe         string `json:"exe,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
	Pod         string `json:"pod,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	// Unit is the systemd service of a process outside containers, so the
	// Console can tie the event to a service on the map.
	Unit string `json:"unit,omitempty"`
	// Scope is "cgroup" when a memory cgroup limit caused the OOM, "host"
	// when the whole host ran out of memory.
	Scope       string `json:"scope"`
	TriggerPID  uint32 `json:"trigger_pid"`
	TriggerComm string `json:"trigger_comm"`
}

type ProcessExit struct {
	PID         uint32 `json:"pid"`
	Comm        string `json:"comm"`
	Exe         string `json:"exe,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
	Pod         string `json:"pod,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Unit        string `json:"unit,omitempty"` // as on OOMKill
	Class       string `json:"class"`
	Signal      string `json:"signal,omitempty"`
	CoreDumped  bool   `json:"core_dumped,omitempty"`
	Status      int    `json:"status,omitempty"`
	SenderPID   uint32 `json:"sender_pid,omitempty"`
	SenderComm  string `json:"sender_comm,omitempty"`
}

type CrashLoop struct {
	Comm        string    `json:"comm"`
	Exe         string    `json:"exe,omitempty"`
	ContainerID string    `json:"container_id,omitempty"`
	Pod         string    `json:"pod,omitempty"`
	Namespace   string    `json:"namespace,omitempty"`
	Unit        string    `json:"unit,omitempty"`
	LastClass   string    `json:"last_class"`
	Count       int       `json:"count"` // exits not reported individually
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
}
