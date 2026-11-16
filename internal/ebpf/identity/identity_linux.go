//go:build linux && (386 || amd64 || arm64)

package identity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/statusharbor/lighthouse/internal/ebpf"
)

// Collector fills the identity Cache from exec and exit tracepoints, after
// seeding it from /proc with the processes already running. It emits no
// customer data, only its own self-metrics; other collectors read Cache.
type Collector struct {
	Cache    *Cache
	ProcRoot string // "/proc", or the host's /proc mounted elsewhere
	Pods     *PodResolver
	Interval time.Duration

	decodeErrors atomic.Uint64
}

// New returns a collector with a 30-second exit grace and room for 64k
// processes.
func New(procRoot string, pods *PodResolver) *Collector {
	return &Collector{Cache: NewCache(30*time.Second, 1<<16), ProcRoot: procRoot, Pods: pods, Interval: 10 * time.Second}
}

func (*Collector) Name() string { return "identity" }

func (*Collector) Requirements() ebpf.Requirements {
	return ebpf.Requirements{
		BTF:          true, // CO-RE read of task_struct.start_boottime
		KernelMemory: true,
		Features: []ebpf.Feature{
			{Name: "raw tracepoint programs", Probe: func() error { return features.HaveProgramType(cebpf.RawTracepoint) }},
			{Name: "ring buffer maps", Probe: func() error { return features.HaveMapType(cebpf.RingBuf) }},
			{Name: "host PID namespace", Probe: HostPIDNamespace},
		},
	}
}

// initPIDNamespaceInode is PROC_PID_INIT_INO, the fixed inode of the
// initial (host) PID namespace.
const initPIDNamespaceInode = 0xEFFFFFFC

// HostPIDNamespace fails unless the agent runs in the host PID namespace.
// The kernel reports host pids, so in a container with its own PID
// namespace (no hostPID: true) nothing would ever resolve.
func HostPIDNamespace() error {
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &st); err != nil {
		return err
	}
	if st.Ino != initPIDNamespaceInode {
		return errors.New("agent is not in the host PID namespace (set hostPID: true)")
	}
	return nil
}

func (c *Collector) Run(ctx context.Context, sink ebpf.Sink) error {
	var objs identityObjects
	if err := loadIdentityObjects(&objs, nil); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	defer func() { _ = objs.Close() }()
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("ring buffer: %w", err)
	}
	defer func() { _ = rd.Close() }()
	for _, tp := range []struct {
		name string
		prog *cebpf.Program
	}{{"sched_process_exec", objs.OnExec}, {"sched_process_exit", objs.OnExit}} {
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: tp.name, Program: tp.prog})
		if err != nil {
			return fmt.Errorf("attach %s: %w", tp.name, err)
		}
		defer func() { _ = l.Close() }()
	}
	// Attach first, then seed: a process starting in between is seen by
	// both, and Put is idempotent.
	c.seed(ctx)

	readErr := make(chan error, 1)
	go func() { readErr <- c.read(ctx, rd) }()

	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = rd.Close()   // unblocks read
			return <-readErr // nil once the closed ring buffer ends the read loop
		case err := <-readErr:
			return err
		case now := <-t.C:
			c.Cache.Sweep(now)
			entries, refused := c.Cache.Stats()
			var lost []uint64
			_ = objs.Lost.Lookup(uint32(0), &lost)
			var lostSum uint64
			for _, v := range lost {
				lostSum += v
			}
			sink.Gauge("lighthouse_ebpf_identity_entries", float64(entries), nil)
			sink.Gauge("lighthouse_ebpf_identity_refused_total", float64(refused), nil)
			sink.Gauge("lighthouse_ebpf_identity_lost_total", float64(lostSum), nil)
			sink.Gauge("lighthouse_ebpf_identity_decode_errors_total", float64(c.decodeErrors.Load()), nil)
		}
	}
}

func (c *Collector) read(ctx context.Context, rd *ringbuf.Reader) error {
	var e identityEvent
	for {
		rec, err := rd.Read()
		if errors.Is(err, os.ErrClosed) || errors.Is(err, ringbuf.ErrClosed) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read ring buffer: %w", err)
		}
		if err := ebpf.DecodeRecord(rec.RawSample, &e); err != nil {
			c.decodeErrors.Add(1)
			continue
		}
		k := KeyFromBootNS(e.Pid, e.StartNs)
		switch e.Type {
		case 1: // EVENT_EXEC
			p := c.describe(ctx, e.Pid)
			p.Comm = commString(e.Comm)
			p.CgroupID = e.CgroupId
			c.Cache.Put(k, p)
		case 2: // EVENT_EXIT
			c.Cache.Exit(k, time.Now())
		default:
			c.decodeErrors.Add(1)
		}
	}
}

// seed adds the processes running before the programs were attached.
func (c *Collector) seed(ctx context.Context) {
	dirs, _ := os.ReadDir(c.ProcRoot)
	for _, d := range dirs {
		pid, err := strconv.ParseUint(d.Name(), 10, 32)
		if err != nil {
			continue
		}
		stat, err := os.ReadFile(filepath.Join(c.ProcRoot, d.Name(), "stat"))
		if err != nil {
			continue // exited meanwhile
		}
		comm, start, ok := parseStat(string(stat))
		if !ok {
			continue
		}
		p := c.describe(ctx, uint32(pid))
		p.Comm = comm
		c.Cache.Put(Key{PID: uint32(pid), StartTicks: start}, p)
	}
}

// Lookup resolves a process from the cache, falling back to /proc for one
// the cache has not seen (the identity collector is off or has not seeded
// yet). A zero StartTicks means "read it from /proc".
func (c *Collector) Lookup(ctx context.Context, k Key) Process {
	dir := filepath.Join(c.ProcRoot, strconv.FormatUint(uint64(k.PID), 10))
	var comm string
	if k.StartTicks == 0 {
		stat, err := os.ReadFile(filepath.Join(dir, "stat"))
		if err != nil {
			return Process{}
		}
		var ok bool
		if comm, k.StartTicks, ok = parseStat(string(stat)); !ok {
			return Process{}
		}
	}
	if p, ok := c.Cache.Get(k); ok {
		return p
	}
	p := c.describe(ctx, k.PID)
	p.Comm = comm
	return p
}

// describe reads executable, container and pod for a live pid. A process
// that already exited yields what could be read.
func (c *Collector) describe(ctx context.Context, pid uint32) Process {
	dir := filepath.Join(c.ProcRoot, strconv.FormatUint(uint64(pid), 10))
	var p Process
	p.Exe, _ = os.Readlink(filepath.Join(dir, "exe"))
	if cg, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		p.ContainerID, p.PodUID = containerFromCgroupFile(string(cg))
		if p.ContainerID == "" {
			p.Unit = unitFromCgroupFile(string(cg))
		}
	}
	if pod, ok := c.Pods.Resolve(ctx, p.PodUID); ok {
		p.Pod, p.Namespace = pod.Name, pod.Namespace
	}
	return p
}

func commString(c [16]int8) string {
	b := make([]byte, 0, len(c))
	for _, v := range c {
		b = append(b, byte(v))
	}
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
