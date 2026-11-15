//go:build linux

package discovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
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
	"github.com/statusharbor/lighthouse/internal/ebpf/identity"
)

// Collector keeps the inventory of TCP listeners on the host: a /proc
// snapshot at start for the ones already open, kernel events after that.
type Collector struct {
	Identity *identity.Collector
	ProcRoot string
	Interval time.Duration

	decodeErrors atomic.Uint64
}

func New(ident *identity.Collector, procRoot string) *Collector {
	return &Collector{Identity: ident, ProcRoot: procRoot, Interval: 15 * time.Second}
}

func (*Collector) Name() string { return "discovery" }

func (*Collector) Requirements() ebpf.Requirements {
	return ebpf.Requirements{
		BTF:          true,
		KernelMemory: true,
		Features: []ebpf.Feature{
			{Name: "raw tracepoint programs", Probe: func() error { return features.HaveProgramType(cebpf.RawTracepoint) }},
			{Name: "ring buffer maps", Probe: func() error { return features.HaveMapType(cebpf.RingBuf) }},
			{Name: "host PID namespace", Probe: identity.HostPIDNamespace},
		},
	}
}

type rawEvent struct {
	open    bool
	ino     uint64
	pid     uint32
	startNS uint64
	key     listenerKey
	comm    string
}

func (c *Collector) Run(ctx context.Context, sink ebpf.Sink) error {
	var objs discoveryObjects
	if err := loadDiscoveryObjects(&objs, nil); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	defer func() { _ = objs.Close() }()
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("ring buffer: %w", err)
	}
	defer func() { _ = rd.Close() }()
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "inet_sock_set_state", Program: objs.OnSockState})
	if err != nil {
		return fmt.Errorf("attach inet_sock_set_state: %w", err)
	}
	defer func() { _ = l.Close() }()

	// Snapshot after attaching and before reading events: a socket opened
	// in between is in both and merges; one closed in between is either
	// not in the snapshot or its close event is applied after it.
	inv, edges := newInventory(time.Now()), newEdgeTotals()
	var public ebpf.PublicLimiter
	self, hostNS := uint32(os.Getpid()), c.netns(1)
	c.bootstrap(ctx, inv, self, hostNS)

	raw := make(chan rawEvent, 256)
	readErr := make(chan error, 1)
	go func() { readErr <- c.read(ctx, rd, raw) }()

	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = rd.Close()
			_ = <-readErr // the read loop's exit; we are stopping anyway
			return nil
		case err := <-readErr:
			return err
		case r := <-raw:
			if !r.open {
				inv.close(r.ino)
				continue
			}
			if r.pid == self {
				continue // the agent's own sockets
			}
			p := c.Identity.Lookup(ctx, identity.KeyFromBootNS(r.pid, r.startNS))
			inv.open(r.ino, r.key, listenerInfo(r.pid, r.comm, p, r.key.NetNS == hostNS))
		case now := <-t.C:
			for _, e := range inv.tick(now) {
				sink.Event(e.kind, now, e.payload)
			}
			if err := c.drainEdges(ctx, objs.Edges, edges, &public, self, now); err != nil {
				return fmt.Errorf("read edges: %w", err)
			}
			edges.emit(now, sink.Gauge)
			var lost []uint64
			_ = objs.Lost.Lookup(uint32(0), &lost)
			var sum uint64
			for _, v := range lost {
				sum += v
			}
			sink.Gauge("lighthouse_ebpf_discovery_listeners", float64(inv.announced()), nil)
			sink.Gauge("lighthouse_ebpf_discovery_overflow_total", float64(inv.overflow), nil)
			sink.Gauge("lighthouse_ebpf_discovery_lost_total", float64(sum), nil)
			sink.Gauge("lighthouse_ebpf_discovery_decode_errors_total", float64(c.decodeErrors.Load()), nil)
		}
	}
}

// meshProxies are service-mesh sidecars: their connections to pod IPs
// duplicate the app's connection to the Service, so they are tagged and
// hidden from the default map.
var meshProxies = map[string]bool{"envoy": true, "pilot-agent": true, "linkerd2-proxy": true}

// drainEdges moves one interval of established connections into the
// totals, resolving each source group to its service identity. The agent's
// own connections (to StatusHarbor, DSC-U-F8) are skipped.
func (c *Collector) drainEdges(ctx context.Context, m *cebpf.Map, t *edgeTotals, public *ebpf.PublicLimiter, self uint32, now time.Time) error {
	var cursor cebpf.MapBatchCursor
	keys := make([]discoveryEdgeKey, 256)
	vals := make([]discoveryEdgeVal, 256)
	for {
		n, err := m.BatchLookupAndDelete(&cursor, keys, vals, nil)
		for i, k := range keys[:n] {
			v := vals[i]
			if v.Pid == self {
				continue
			}
			comm := cstr(k.Comm)
			src := sourceIdentity(listenerInfo(v.Pid, comm, c.Identity.Lookup(ctx, identity.KeyFromBootNS(v.Pid, v.StartNs)), false))
			addr := netip.AddrFrom16(k.Daddr)
			if k.Family == unix.AF_INET {
				addr = netip.AddrFrom4([4]byte(k.Daddr[:4]))
			}
			addr = addr.Unmap()
			t.add(edge{Src: src, Dst: public.Name(addr, strconv.Itoa(int(k.Dport))), Port: k.Dport, Infra: infraDestination(addr, k.Dport), Proxy: meshProxies[comm]}, v.Count, now)
		}
		if errors.Is(err, cebpf.ErrKeyNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func listenerInfo(pid uint32, comm string, p identity.Process, hostNet bool) Listener {
	if p.Comm != "" {
		comm = p.Comm
	}
	return Listener{
		HostNetwork: hostNet, PID: pid, Comm: comm, Exe: p.Exe,
		ContainerID: p.ContainerID, Pod: p.Pod, Namespace: p.Namespace, Unit: p.Unit,
	}
}

// netns returns the network namespace inode of a pid, 0 if unreadable.
func (c *Collector) netns(pid uint32) uint32 {
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(c.ProcRoot, strconv.FormatUint(uint64(pid), 10), "ns", "net"), &st); err != nil {
		return 0
	}
	return uint32(st.Ino)
}

// bootstrap adds the listeners open before the program was attached: one
// pass over every process's fds maps socket inodes to pids, then each
// network namespace's /proc/<pid>/net/tcp{,6} lists its listeners.
func (c *Collector) bootstrap(ctx context.Context, inv *inventory, self, hostNS uint32) {
	owner := map[uint64]uint32{} // socket inode -> pid
	nsPID := map[uint32]uint32{} // netns -> a pid in it
	dirs, _ := os.ReadDir(c.ProcRoot)
	for _, d := range dirs {
		pid64, err := strconv.ParseUint(d.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		if ns := c.netns(pid); ns != 0 {
			if _, ok := nsPID[ns]; !ok {
				nsPID[ns] = pid
			}
		}
		fdDir := filepath.Join(c.ProcRoot, d.Name(), "fd")
		fds, _ := os.ReadDir(fdDir)
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if ino, ok := socketInode(link); ok {
				if _, seen := owner[ino]; !seen {
					owner[ino] = pid
				}
			}
		}
	}
	for ns, nsp := range nsPID {
		for _, file := range []string{"tcp", "tcp6"} {
			f, err := os.Open(filepath.Join(c.ProcRoot, strconv.FormatUint(uint64(nsp), 10), "net", file))
			if err != nil {
				continue
			}
			for _, pl := range parseProcNet(f) {
				pid, ok := owner[pl.ino]
				if !ok || pid == self {
					continue // no process holds it (orphaned) or it is ours
				}
				info := listenerInfo(pid, "", c.Identity.Lookup(ctx, identity.Key{PID: pid}), ns == hostNS)
				info.Bootstrap = true
				inv.open(pl.ino, keyFor(ns, pl.addr, pl.port), info)
			}
			_ = f.Close()
		}
	}
}

func (c *Collector) read(ctx context.Context, rd *ringbuf.Reader, out chan<- rawEvent) error {
	var e discoveryEvent
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
		addr := netip.AddrFrom16(e.Addr)
		if e.Family == unix.AF_INET {
			addr = netip.AddrFrom4([4]byte(e.Addr[:4]))
		}
		r := rawEvent{
			open: e.Type == 1, ino: e.Ino, pid: e.Pid, startNS: e.StartNs,
			key: keyFor(e.Netns, addr, e.Port), comm: cstr(e.Comm),
		}
		select {
		case out <- r:
		case <-ctx.Done():
			return nil
		}
	}
}

func cstr(c [16]int8) string {
	b := make([]byte, len(c))
	for i, v := range c {
		b[i] = byte(v)
	}
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
