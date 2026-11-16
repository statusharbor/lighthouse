package incident

import (
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf/identity"
)

// rawEvent is one decoded ring buffer record, platform-neutral so the
// rules below are tested without a kernel.
type rawEvent struct {
	Type       uint32 // 1 OOM, 2 exit
	At         time.Time
	PID        uint32
	StartNS    uint64
	OtherPID   uint32
	ExitCode   int32
	PPID       uint32
	MemcgOOM   bool
	SenderSig  uint32
	Comm       string
	OtherComm  string
	ParentComm string
}

type emission struct {
	kind    string
	at      time.Time
	payload any
}

// processor turns raw events into envelope payloads: identity enrichment,
// the tracked-service filter and crash-loop collapsing.
type processor struct {
	cache      *identity.Cache         // nil: no enrichment
	isListener func(identity.Key) bool // nil until plan 03
	collapse   *collapser
}

func newProcessor(cache *identity.Cache, isListener func(identity.Key) bool) *processor {
	return &processor{cache: cache, isListener: isListener, collapse: newCollapser(time.Minute, 3)}
}

// lookup resolves by pid and start time, so after pid reuse the old
// process's events never pick up the new owner's identity (INC-U-F10).
func (p *processor) lookup(pid uint32, startNS uint64) (identity.Key, identity.Process) {
	k := identity.KeyFromBootNS(pid, startNS)
	if p.cache == nil {
		return k, identity.Process{}
	}
	proc, _ := p.cache.Get(k)
	return k, proc
}

func (p *processor) handle(r rawEvent) []emission {
	switch r.Type {
	case 1:
		_, proc := p.lookup(r.PID, r.StartNS)
		scope := "host"
		if r.MemcgOOM {
			scope = "cgroup"
		}
		return []emission{{KindOOMKill, r.At, OOMKill{
			PID: r.PID, Comm: r.Comm, Exe: proc.Exe, ContainerID: proc.ContainerID,
			Pod: proc.Pod, Namespace: proc.Namespace, Unit: proc.Unit, Scope: scope,
			TriggerPID: r.OtherPID, TriggerComm: r.OtherComm,
		}}}
	case 2:
		return p.handleExit(r)
	}
	return nil
}

func (p *processor) handleExit(r rawEvent) []emission {
	sig, core, status := DecodeExit(r.ExitCode)
	class := Classify(sig, status)
	if class == "" {
		return nil
	}
	key, proc := p.lookup(r.PID, r.StartNS)
	tracked := trackedParent(r.PPID, r.ParentComm) || (p.isListener != nil && p.isListener(key))
	if !alwaysReported(class) && !tracked {
		return nil
	}
	ev := ProcessExit{
		PID: r.PID, Comm: r.Comm, Exe: proc.Exe, ContainerID: proc.ContainerID,
		Pod: proc.Pod, Namespace: proc.Namespace, Unit: proc.Unit, Class: class, CoreDumped: core, Status: status,
	}
	if sig != 0 {
		ev.Signal = SignalName(sig)
	}
	if r.SenderSig != 0 && int(r.SenderSig) == sig {
		ev.SenderPID, ev.SenderComm = r.OtherPID, r.OtherComm
	}

	var out []emission
	emit, summary := p.collapse.observe(r.Comm+"\x00"+proc.ContainerID, r.At, ev)
	if summary != nil {
		out = append(out, emission{KindCrashLoop, summary.WindowEnd, *summary})
	}
	if emit {
		out = append(out, emission{KindProcessExit, r.At, ev})
	}
	return out
}

func (p *processor) flush(now time.Time) []emission {
	var out []emission
	for _, s := range p.collapse.flush(now) {
		out = append(out, emission{KindCrashLoop, s.WindowEnd, s})
	}
	return out
}
