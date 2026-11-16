//go:build linux

package incident

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/statusharbor/lighthouse/internal/ebpf"
	"github.com/statusharbor/lighthouse/internal/ebpf/identity"
)

// Collector reports OOM kills and abnormal exits as events. Identity
// enrichment needs the identity collector to be running too; without it
// events carry pid and command only.
type Collector struct {
	Identity   *identity.Cache
	IsListener func(identity.Key) bool
	Interval   time.Duration

	decodeErrors atomic.Uint64
}

func New(cache *identity.Cache) *Collector {
	return &Collector{Identity: cache, Interval: 10 * time.Second}
}

func (*Collector) Name() string { return "incident" }

func (*Collector) Requirements() ebpf.Requirements {
	return ebpf.Requirements{
		BTF:          true,
		KernelMemory: true,
		Features: []ebpf.Feature{
			{Name: "raw tracepoint programs", Probe: func() error { return features.HaveProgramType(cebpf.RawTracepoint) }},
			{Name: "ring buffer maps", Probe: func() error { return features.HaveMapType(cebpf.RingBuf) }},
			{Name: "LRU hash maps", Probe: func() error { return features.HaveMapType(cebpf.LRUHash) }},
		},
	}
}

func (c *Collector) Run(ctx context.Context, sink ebpf.Sink) error {
	var objs incidentObjects
	if err := loadIncidentObjects(&objs, nil); err != nil {
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
	}{
		{"signal_generate", objs.OnSignal}, {"sched_process_exit", objs.OnExit},
		{"inet_sock_set_state", objs.OnSockState}, {"tcp_send_reset", objs.OnSendReset},
		{"tcp_receive_reset", objs.OnReceiveReset}, {"tcp_retransmit_skb", objs.OnRetransmit},
	} {
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: tp.name, Program: tp.prog})
		if err != nil {
			return fmt.Errorf("attach %s: %w", tp.name, err)
		}
		defer func() { _ = l.Close() }()
	}
	// oom_kill_process is an internal kernel function and may be missing
	// or renamed; exits still work without it, and the gauge says so.
	oomAttached := 1.0
	if kp, err := link.Kprobe("oom_kill_process", objs.OnOomKill, nil); err != nil {
		oomAttached = 0
		slog.Warn("ebpf incident: OOM kill events unavailable on this kernel", "error", err)
	} else {
		defer func() { _ = kp.Close() }()
	}

	proc := newProcessor(c.Identity, c.IsListener)
	conns, drainOK := newNetTotals(), true
	raw := make(chan rawEvent, 256)
	readErr := make(chan error, 1)
	go func() { readErr <- c.read(ctx, rd, raw) }()

	t := time.NewTicker(c.Interval)
	defer t.Stop()
	emit := func(es []emission) {
		for _, e := range es {
			sink.Event(e.kind, e.at, e.payload)
		}
	}
	for {
		select {
		case <-ctx.Done():
			_ = rd.Close()
			err := <-readErr                            // nil once the closed ring buffer ends the read loop
			emit(proc.flush(time.Now().Add(time.Hour))) // close open crash-loop windows
			return err
		case err := <-readErr:
			return err
		case r := <-raw:
			emit(proc.handle(r))
		case now := <-t.C:
			emit(proc.flush(now))
			var lost []uint64
			_ = objs.Lost.Lookup(uint32(0), &lost)
			var sum uint64
			for _, v := range lost {
				sum += v
			}
			sink.Gauge("lighthouse_ebpf_incident_lost_total", float64(sum), nil)
			sink.Gauge("lighthouse_ebpf_incident_decode_errors_total", float64(c.decodeErrors.Load()), nil)
			sink.Gauge("lighthouse_ebpf_incident_oom_attached", oomAttached, nil)
			if drainOK {
				if err := drainConns(objs.Conns, conns, now); err != nil {
					drainOK = false
					slog.Warn("ebpf incident: TCP counters unavailable", "error", err)
				}
				if ebpf.Limited("incident") {
					conns = newNetTotals() // the plan has the top line only: counters are not sent
				} else {
					conns.emit(now, sink.Gauge)
				}
			}
		}
	}
}

func (c *Collector) read(ctx context.Context, rd *ringbuf.Reader, out chan<- rawEvent) error {
	var e incidentEvent
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
		r := rawEvent{
			Type: e.Type, At: ebpf.WallTime(e.TsNs), PID: e.Pid, StartNS: e.StartNs,
			OtherPID: e.OtherPid, ExitCode: e.ExitCode, PPID: e.Ppid, MemcgOOM: e.Flags&1 != 0,
			SenderSig: e.SenderSig, Comm: cstr(e.Comm), OtherComm: cstr(e.OtherComm), ParentComm: cstr(e.ParentComm),
		}
		select {
		case out <- r:
		case <-ctx.Done():
			return nil
		}
	}
}

// drainConns moves the kernel's TCP counters into the totals and clears
// them, so the kernel map only holds one interval's sockets.
func drainConns(m *cebpf.Map, t *netTotals, now time.Time) error {
	var cursor cebpf.MapBatchCursor
	keys := make([]incidentConnKey, 256)
	vals := make([]uint64, 256)
	for {
		n, err := m.BatchLookupAndDelete(&cursor, keys, vals, nil)
		for i, k := range keys[:n] {
			t.add(connKey{Addr: k.Addr, RPort: k.Rport, LPort: k.Lport, IPv6: k.Family == 10, Kind: k.Kind, Err: k.Err}, vals[i], now)
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
	b := make([]byte, len(c))
	for i, v := range c {
		b[i] = byte(v)
	}
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
