//go:build linux && (386 || amd64 || arm64)

package procusage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"

	"github.com/statusharbor/lighthouse/internal/ebpf"
	"github.com/statusharbor/lighthouse/internal/ebpf/identity"
	"github.com/statusharbor/lighthouse/internal/usage"
)

// Collector feeds the usage accountant with exit CPU and file I/O and
// reports disk latency percentiles. A missing hook (no vfs kprobes, no
// block tracepoints) leaves the collector running degraded.
type Collector struct {
	Identity *identity.Collector
	Acct     *usage.Accountant
	Poller   *usage.Poller
	Interval time.Duration
}

func New(ident *identity.Collector, acct *usage.Accountant, poller *usage.Poller) *Collector {
	return &Collector{Identity: ident, Acct: acct, Poller: poller, Interval: 10 * time.Second}
}

func (*Collector) Name() string { return "usage" }

func (*Collector) Requirements() ebpf.Requirements {
	return ebpf.Requirements{
		BTF:          true,
		KernelMemory: true,
		Features: []ebpf.Feature{
			{Name: "raw tracepoint programs", Probe: func() error { return features.HaveProgramType(cebpf.RawTracepoint) }},
			{Name: "host PID namespace", Probe: identity.HostPIDNamespace},
		},
	}
}

// requestArgIndex reads the block_rq_issue tracepoint's prototype from
// kernel BTF: since 5.11 the request is its first argument, before that the
// request queue came first.
func requestArgIndex() uint32 {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return 0
	}
	var td *btf.Typedef
	if err := spec.TypeByName("btf_trace_block_rq_issue", &td); err != nil {
		return 0
	}
	if ptr, ok := td.Type.(*btf.Pointer); ok {
		if fp, ok := ptr.Target.(*btf.FuncProto); ok && len(fp.Params) == 3 {
			return 1
		}
	}
	return 0
}

func (c *Collector) Run(ctx context.Context, sink ebpf.Sink) error {
	spec, err := loadUsage()
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}
	if err := spec.Variables["rq_arg"].Set(requestArgIndex()); err != nil {
		return fmt.Errorf("set rq_arg: %w", err)
	}
	var objs usageObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	defer func() { _ = objs.Close() }()

	exitLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sched_process_exit", Program: objs.OnExit})
	if err != nil {
		return fmt.Errorf("attach sched_process_exit: %w", err)
	}
	defer func() { _ = exitLink.Close() }()

	var problems []string
	attach := func(what string, f func() (link.Link, error)) {
		l, err := f()
		if err != nil {
			problems = append(problems, what+": "+err.Error())
			return
		}
		go func() { <-ctx.Done(); _ = l.Close() }()
	}
	attach("no file I/O", func() (link.Link, error) { return link.Kprobe("vfs_read", objs.OnRead, nil) })
	attach("no file I/O", func() (link.Link, error) { return link.Kretprobe("vfs_read", objs.OnReadRet, nil) })
	attach("no file I/O", func() (link.Link, error) { return link.Kprobe("vfs_write", objs.OnWrite, nil) })
	attach("no file I/O", func() (link.Link, error) { return link.Kretprobe("vfs_write", objs.OnWriteRet, nil) })
	attach("no disk latency", func() (link.Link, error) {
		return link.AttachRawTracepoint(link.RawTracepointOptions{Name: "block_rq_issue", Program: objs.OnRqIssue})
	})
	attach("no disk latency", func() (link.Link, error) {
		return link.AttachRawTracepoint(link.RawTracepointOptions{Name: "block_rq_complete", Program: objs.OnRqComplete})
	})
	if len(problems) > 0 {
		if d, ok := sink.(ebpf.Degrader); ok {
			d.Degrade(strings.Join(problems, "; "))
		}
	}

	names := map[uint32]string{}
	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := c.drainExits(ctx, objs.Exits); err != nil {
				return fmt.Errorf("read exits: %w", err)
			}
			if err := c.drainFileIO(ctx, objs.Fileio); err != nil {
				return fmt.Errorf("read file I/O: %w", err)
			}
			if err := emitLatency(objs.Disks, names, sink); err != nil {
				return fmt.Errorf("read disk latency: %w", err)
			}
		}
	}
}

func (c *Collector) group(ctx context.Context, k identity.Key, comm string) string {
	p := c.Identity.Lookup(ctx, k)
	if p.ContainerID == "" && p.Unit == "" && p.Pod == "" && c.Poller != nil {
		if g := c.Poller.GroupOf(ctx, k, comm); g != "" {
			return g
		}
	}
	return usage.Group(p, comm, false)
}

func (c *Collector) drainExits(ctx context.Context, m *cebpf.Map) error {
	var cursor cebpf.MapBatchCursor
	keys := make([]usageProcKey, 256)
	vals := make([]usageCpuVal, 256)
	for {
		n, err := m.BatchLookupAndDelete(&cursor, keys, vals, nil)
		for i, k := range keys[:n] {
			key := identity.KeyFromBootNS(k.Tgid, k.StartNs)
			c.Acct.AddExit(key, vals[i].CpuNs, c.group(ctx, key, cstr(vals[i].Comm)))
		}
		if errors.Is(err, cebpf.ErrKeyNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (c *Collector) drainFileIO(ctx context.Context, m *cebpf.Map) error {
	var cursor cebpf.MapBatchCursor
	keys := make([]usageProcKey, 256)
	vals := make([]usageIoVal, 256)
	self := uint32(os.Getpid())
	for {
		n, err := m.BatchLookupAndDelete(&cursor, keys, vals, nil)
		for i, k := range keys[:n] {
			if k.Tgid == self {
				continue
			}
			key := identity.KeyFromBootNS(k.Tgid, k.StartNs)
			c.Acct.AddFileIO(c.group(ctx, key, cstr(vals[i].Comm)), vals[i].Read+vals[i].Write)
		}
		if errors.Is(err, cebpf.ErrKeyNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// emitLatency reads and clears the per-device histograms and reports p50,
// p95 and p99 per device name.
func emitLatency(m *cebpf.Map, names map[uint32]string, sink ebpf.Sink) error {
	var cursor cebpf.MapBatchCursor
	keys := make([]uint32, 64)
	vals := make([]usageLatency, 64)
	for {
		n, err := m.BatchLookupAndDelete(&cursor, keys, vals, nil)
		for i, dev := range keys[:n] {
			name, ok := names[dev]
			if !ok {
				name = fmt.Sprintf("%d:%d", dev>>20, dev&0xfffff)
				if f, err := os.Open("/sys/dev/block/" + strconv.Itoa(int(dev>>20)) + ":" + strconv.Itoa(int(dev&0xfffff)) + "/uevent"); err == nil {
					if dn := devName(f); dn != "" {
						name = dn
					}
					_ = f.Close()
				}
				names[dev] = name
			}
			for _, q := range []float64{0.5, 0.95, 0.99} {
				if ms, ok := quantileMS(vals[i].Buckets[:], q); ok {
					sink.Gauge("lighthouse_ebpf_disk_latency_ms", ms, map[string]string{"device": name, "quantile": strconv.FormatFloat(q, 'f', -1, 64)})
				}
			}
		}
		if errors.Is(err, cebpf.ErrKeyNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func cstr(c [16]int8) string {
	b := make([]byte, 0, len(c))
	for _, v := range c {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}
