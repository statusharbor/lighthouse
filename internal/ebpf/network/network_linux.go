//go:build linux && (386 || amd64 || arm64)

package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// Collector measures TCP path quality per source service and destination,
// and DNS per resolver (docs/eBPF/04-network-quality.md). Without the
// socket iterator it runs on close-time data only; without cgroup v2 (or
// CAP_NET_ADMIN) it runs without DNS. Either way its status says degraded.
type Collector struct {
	Identity *identity.Collector
	ProcRoot string
	Interval time.Duration
	// Usage, when set, receives per-process TCP bytes (plan 05) grouped by
	// GroupOf.
	Usage interface {
		AddNetwork(group string, bytes uint64)
	}
	GroupOf func(ctx context.Context, k identity.Key, comm string) string

	decodeErrors atomic.Uint64
}

func New(ident *identity.Collector, procRoot string) *Collector {
	return &Collector{Identity: ident, ProcRoot: procRoot, Interval: 15 * time.Second}
}

func (*Collector) Name() string { return "network" }

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

// tcpObjects is netquality without the iterator program, for kernels that
// cannot load it.
type tcpObjects struct {
	OnState  *cebpf.Program `ebpf:"on_state"`
	OnAccept *cebpf.Program `ebpf:"on_accept"`
	netqualityMaps
}

func (o *tcpObjects) Close() error {
	return errors.Join(o.OnState.Close(), o.OnAccept.Close(), o.netqualityMaps.Close())
}

func (c *Collector) Run(ctx context.Context, sink ebpf.Sink) error {
	degrade := func(detail string) {
		if d, ok := sink.(ebpf.Degrader); ok {
			d.Degrade(detail)
		}
	}
	var problems []string

	spec, err := loadNetquality()
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}
	var objs tcpObjects
	var iterProg *cebpf.Program
	var full netqualityObjects
	if err := spec.LoadAndAssign(&full, nil); err == nil {
		objs = tcpObjects{OnState: full.OnState, OnAccept: full.OnAccept, netqualityMaps: full.netqualityMaps}
		iterProg = full.DumpTcp
		defer func() { _ = iterProg.Close() }()
	} else {
		delete(spec.Programs, "dump_tcp")
		if err2 := spec.LoadAndAssign(&objs, nil); err2 != nil {
			return fmt.Errorf("load: %w", err2)
		}
		problems = append(problems, "no socket iterator, close-time data only: "+err.Error())
	}
	defer func() { _ = objs.Close() }()

	var iter *link.Iter
	if iterProg != nil {
		if iter, err = link.AttachIter(link.IterOptions{Program: iterProg}); err != nil {
			problems = append(problems, "no socket iterator, close-time data only: "+err.Error())
		} else {
			defer func() { _ = iter.Close() }()
		}
	}
	if kp, err := link.Kretprobe("inet_csk_accept", objs.OnAccept, nil); err != nil {
		problems = append(problems, "server-side traffic not attributed to processes: "+err.Error())
	} else {
		defer func() { _ = kp.Close() }()
	}
	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "inet_sock_set_state", Program: objs.OnState})
	if err != nil {
		return fmt.Errorf("attach inet_sock_set_state: %w", err)
	}
	defer func() { _ = tp.Close() }()
	closes, err := ringbuf.NewReader(objs.Closes)
	if err != nil {
		return fmt.Errorf("ring buffer: %w", err)
	}
	defer func() { _ = closes.Close() }()

	dnsEvents, dnsLost, stopDNS, err := c.startDNS()
	if err != nil {
		problems = append(problems, "no DNS data: "+err.Error())
	} else {
		defer stopDNS()
	}
	if len(problems) > 0 {
		degrade(strings.Join(problems, "; "))
	}

	fl, dm := newFlows(), newDNSMatcher()
	if c.Usage != nil {
		fl.usage = c.Usage.AddNetwork
	}
	closed := make(chan sample, 1024)
	readErr := make(chan error, 2)
	go func() { readErr <- c.readCloses(ctx, closes, closed) }()
	var dnsCh chan dnsHeader
	if dnsEvents != nil {
		dnsCh = make(chan dnsHeader, 1024)
		go func() { readErr <- c.readDNS(ctx, dnsEvents, dnsCh) }()
	}

	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = closes.Close()
			if dnsEvents != nil {
				_ = dnsEvents.Close()
			}
			return nil
		case err := <-readErr:
			return err
		case s := <-closed:
			fl.observe(s, time.Now())
		case e := <-dnsCh:
			dm.observe(e)
		case now := <-t.C:
			if iter != nil {
				if err := c.iterate(ctx, iter, fl, now); err != nil {
					return fmt.Errorf("socket iterator: %w", err)
				}
			}
			fl.emit(now, sink.Gauge)
			if err := emitConnects(objs.Connects, now, sink); err != nil {
				return fmt.Errorf("read connect times: %w", err)
			}
			dm.expire(monotonicNS())
			dm.emit(sink.Gauge)
			sink.Gauge("lighthouse_ebpf_network_lost_total", float64(sumPerCPU(objs.Lost)+sumPerCPU(dnsLost)), nil)
			sink.Gauge("lighthouse_ebpf_network_decode_errors_total", float64(c.decodeErrors.Load()), nil)
		}
	}
}

func monotonicNS() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Nano())
}

func sumPerCPU(m *cebpf.Map) uint64 {
	if m == nil {
		return 0
	}
	var vals []uint64
	_ = m.Lookup(uint32(0), &vals)
	var sum uint64
	for _, v := range vals {
		sum += v
	}
	return sum
}

// convert turns a kernel sample into the platform-neutral one, resolving
// the owner to its service identity.
func (c *Collector) convert(ctx context.Context, s *netqualitySample) sample {
	dst := netip.AddrFrom16(s.Daddr)
	if s.Family == unix.AF_INET {
		dst = netip.AddrFrom4([4]byte(s.Daddr[:4]))
	}
	src, group := "", ""
	if s.Pid != 0 {
		k := identity.KeyFromBootNS(s.Pid, s.StartNs)
		src = identity.SourceID(c.Identity.Lookup(ctx, k), cstr(s.Comm))
		if c.GroupOf != nil {
			group = c.GroupOf(ctx, k, cstr(s.Comm))
		}
	}
	return sample{
		SK: s.Sk, BytesAcked: s.BytesAcked, BytesReceived: s.BytesReceived, SRTTus: s.SrttUs,
		Retrans: s.TotalRetrans, SegsOut: s.DataSegsOut, LPort: s.Lport, DPort: s.Dport, Dst: dst, Src: src,
		Group: group, Closed: s.Flags&1 != 0, Inbound: s.Flags&2 != 0,
	}
}

// iterate runs one socket iterator pass. The agent's own sockets count:
// its checks are the path a monitor's network card and incident hint
// describe (plan 04).
func (c *Collector) iterate(ctx context.Context, it *link.Iter, fl *flows, now time.Time) error {
	r, err := it.Open()
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	listed := map[uint64]bool{}
	var s netqualitySample
	buf := make([]byte, binary.Size(s))
	for {
		if _, err := io.ReadFull(r, buf); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		if err := binary.Read(bytes.NewReader(buf), binary.NativeEndian, &s); err != nil {
			c.decodeErrors.Add(1)
			continue
		}
		listed[s.Sk] = true
		fl.observe(c.convert(ctx, &s), now)
	}
	fl.endPass(listed)
	return nil
}

func (c *Collector) readCloses(ctx context.Context, rd *ringbuf.Reader, out chan<- sample) error {
	var s netqualitySample
	for {
		rec, err := rd.Read()
		if errors.Is(err, os.ErrClosed) || errors.Is(err, ringbuf.ErrClosed) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read closes: %w", err)
		}
		if err := ebpf.DecodeRecord(rec.RawSample, &s); err != nil {
			c.decodeErrors.Add(1)
			continue
		}
		select {
		case out <- c.convert(ctx, &s):
		case <-ctx.Done():
			return nil
		}
	}
}

// emitConnects reads and clears the connect-time histograms and reports
// p50 and p95 per destination.
func emitConnects(m *cebpf.Map, now time.Time, sink ebpf.Sink) error {
	var cursor cebpf.MapBatchCursor
	keys := make([]netqualityDestKey, 256)
	vals := make([]netqualityConnectHist, 256)
	for {
		n, err := m.BatchLookupAndDelete(&cursor, keys, vals, nil)
		for i, k := range keys[:n] {
			dst := netip.AddrFrom16(k.Daddr)
			if k.Family == unix.AF_INET {
				dst = netip.AddrFrom4([4]byte(k.Daddr[:4]))
			}
			dst = dst.Unmap()
			if dst.IsLoopback() {
				continue
			}
			for _, q := range []float64{0.5, 0.95} {
				if ms, ok := connectQuantile(vals[i].Buckets[:], q); ok {
					sink.Gauge("lighthouse_ebpf_flow_connect_ms", ms, map[string]string{
						"dst": dst.String(), "dst_port": strconv.Itoa(int(k.Dport)), "quantile": strconv.FormatFloat(q, 'f', -1, 64),
					})
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

// startDNS attaches the DNS programs to the host's root cgroup (cgroup v2).
// In a container that is /proc/1/root/sys/fs/cgroup under ProcRoot.
func (c *Collector) startDNS() (*ringbuf.Reader, *cebpf.Map, func(), error) {
	root := filepath.Join(c.ProcRoot, "1", "root", "sys", "fs", "cgroup")
	var st unix.Statfs_t
	if err := unix.Statfs(root, &st); err != nil || st.Type != unix.CGROUP2_SUPER_MAGIC {
		root = "/sys/fs/cgroup"
		if err := unix.Statfs(root, &st); err != nil || st.Type != unix.CGROUP2_SUPER_MAGIC {
			return nil, nil, nil, errors.New("cgroup v2 is not mounted")
		}
	}
	var objs dnsObjects
	if err := loadDnsObjects(&objs, nil); err != nil {
		return nil, nil, nil, fmt.Errorf("load: %w", err)
	}
	var links []link.Link
	stop := func() {
		for _, l := range links {
			_ = l.Close()
		}
		_ = objs.Close()
	}
	for _, a := range []struct {
		prog *cebpf.Program
		at   cebpf.AttachType
	}{{objs.DnsEgress, cebpf.AttachCGroupInetEgress}, {objs.DnsIngress, cebpf.AttachCGroupInetIngress}} {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: root, Attach: a.at, Program: a.prog})
		if err != nil {
			stop()
			return nil, nil, nil, fmt.Errorf("attach to %s: %w", root, err)
		}
		links = append(links, l)
	}
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		stop()
		return nil, nil, nil, err
	}
	return rd, objs.Lost, func() { _ = rd.Close(); stop() }, nil
}

func (c *Collector) readDNS(ctx context.Context, rd *ringbuf.Reader, out chan<- dnsHeader) error {
	var k dnsEvent
	for {
		rec, err := rd.Read()
		if errors.Is(err, os.ErrClosed) || errors.Is(err, ringbuf.ErrClosed) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read dns: %w", err)
		}
		if err := ebpf.DecodeRecord(rec.RawSample, &k); err != nil {
			c.decodeErrors.Add(1)
			continue
		}
		r := netip.AddrFrom16(k.Resolver)
		if k.Family == 4 {
			r = netip.AddrFrom4([4]byte(k.Resolver[:4]))
		}
		select {
		case out <- dnsHeader{TsNS: k.TsNs, Resolver: r, ClientPort: k.ClientPort, TxID: k.Txid, Flags: k.Flags, Response: k.Response == 1}:
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
