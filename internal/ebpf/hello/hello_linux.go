//go:build linux && (386 || amd64 || arm64)

// Package hello is the foundation's empty collector: it counts process
// starts with one tracepoint so loading, status reporting and transport
// are proven on every kernel before a real feature ships.
package hello

import (
	"context"
	"fmt"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"

	"github.com/statusharbor/lighthouse/internal/ebpf"
)

// Collector reports the number of exec calls seen since it started, once
// per Interval.
type Collector struct {
	Interval time.Duration
}

func New() *Collector { return &Collector{Interval: time.Minute} }

func (*Collector) Name() string { return "hello" }

func (*Collector) Requirements() ebpf.Requirements {
	return ebpf.Requirements{Features: []ebpf.Feature{
		{Name: "raw tracepoint programs", Probe: func() error { return features.HaveProgramType(cebpf.RawTracepoint) }},
		{Name: "per-CPU array maps", Probe: func() error { return features.HaveMapType(cebpf.PerCPUArray) }},
	}}
}

func (c *Collector) Run(ctx context.Context, sink ebpf.Sink) error {
	var objs helloObjects
	if err := loadHelloObjects(&objs, nil); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	defer func() { _ = objs.Close() }()
	// Not pinned: the link and maps go away with the process (criterion 5).
	// Raw tracepoint: attached by name, so no tracefs mount is needed in
	// the container.
	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sched_process_exec", Program: objs.CountExec})
	if err != nil {
		return fmt.Errorf("attach sched_process_exec: %w", err)
	}
	defer func() { _ = tp.Close() }()

	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			n, err := c.read(objs.ExecCount)
			if err != nil {
				return err
			}
			sink.Gauge("lighthouse_ebpf_hello_execs_total", float64(n), nil)
		}
	}
}

func (*Collector) read(m *cebpf.Map) (uint64, error) {
	var perCPU []uint64
	if err := m.Lookup(uint32(0), &perCPU); err != nil {
		return 0, fmt.Errorf("read exec_count: %w", err)
	}
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum, nil
}
