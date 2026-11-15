//go:build linux

package overhead

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf"
	"github.com/statusharbor/lighthouse/internal/ebpf/discovery"
	"github.com/statusharbor/lighthouse/internal/ebpf/identity"
	"github.com/statusharbor/lighthouse/internal/ebpf/incident"
	"github.com/statusharbor/lighthouse/internal/ebpf/network"
	"github.com/statusharbor/lighthouse/internal/ebpf/procusage"
	"github.com/statusharbor/lighthouse/internal/usage"
)

type nopSink struct{}

func (nopSink) Gauge(string, float64, map[string]string) {}
func (nopSink) Event(string, time.Time, any)             {}

func cpuTime() time.Duration {
	var self, kids syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &self)
	_ = syscall.Getrusage(syscall.RUSAGE_CHILDREN, &kids)
	tv := func(t syscall.Timeval) time.Duration { return time.Duration(t.Sec)*time.Second + time.Duration(t.Usec)*time.Microsecond }
	return tv(self.Utime) + tv(self.Stime) + tv(kids.Utime) + tv(kids.Stime)
}

// load runs the plan 01 reference load, scaled by OVERHEAD_SCALE (default
// 0.1 so it fits a CI runner): TCP connects, process starts and file writes
// per second, for d.
func load(t *testing.T, d time.Duration) {
	scale := 0.1
	if v, err := strconv.ParseFloat(os.Getenv("OVERHEAD_SCALE"), 64); err == nil {
		scale = v
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	f, err := os.CreateTemp(t.TempDir(), "load")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	rate := func(perSec float64, op func()) func(ctx context.Context) {
		return func(ctx context.Context) {
			tick := time.NewTicker(time.Duration(float64(time.Second) / (perSec * scale)))
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					op()
				}
			}
		}
	}
	buf := make([]byte, 4096)
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	var wg sync.WaitGroup
	for _, run := range []func(context.Context){
		rate(5000, func() { // new TCP connections
			if c, err := net.Dial("tcp4", ln.Addr().String()); err == nil {
				_ = c.Close()
			}
		}),
		rate(500, func() { _ = exec.Command("/bin/true").Run() }), // process starts
		rate(20000, func() { _, _ = f.WriteAt(buf, 0) }),          // file writes
	} {
		wg.Add(1)
		go func() { defer wg.Done(); run(ctx) }()
	}
	wg.Wait()
}

// TestOverhead runs the reference load with the collectors of plans 02 to
// 05 off and on and reports the difference against the budget (under 2%
// of one core at the reference load, docs/eBPF/00-overview.md). It reports
// rather than fails: CI runners are noisy, the number is the deliverable.
func TestOverhead(t *testing.T) {
	if os.Getenv("OVERHEAD_BENCH") == "" {
		t.Skip("set OVERHEAD_BENCH=1 to run the overhead benchmark")
	}
	d := 20 * time.Second
	start := cpuTime()
	load(t, d)
	off := cpuTime() - start

	ident := identity.New("/proc", identity.NewPodResolver(nil, time.Minute))
	acct := usage.NewAccountant()
	collectors := []ebpf.Collector{ident, incident.New(ident.Cache), discovery.New(ident, "/proc"),
		network.New(ident, "/proc"), procusage.New(ident, acct, usage.NewPoller(acct, "/proc", nil))}
	if reason, _ := ebpf.Check(collectors[0].Requirements(), ebpf.ProbeHost()); reason != "" {
		t.Skipf("eBPF not available here: %s", reason)
	}
	// OVERHEAD_ONLY=<collector name> measures one collector (identity
	// always runs: the others depend on it).
	if only := os.Getenv("OVERHEAD_ONLY"); only != "" {
		kept := []ebpf.Collector{ident}
		for _, c := range collectors[1:] {
			if c.Name() == only {
				kept = append(kept, c)
			}
		}
		collectors = kept
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, c := range collectors {
		wg.Add(1)
		go func() { defer wg.Done(); _ = c.Run(ctx, nopSink{}) }()
	}
	time.Sleep(2 * time.Second) // attached
	start = cpuTime()
	load(t, d)
	on := cpuTime() - start
	cancel()
	wg.Wait()

	extra := (on - off).Seconds() / d.Seconds() * 100
	t.Logf("collectors %q, reference load x%s for %s: CPU %.2fs with eBPF off, %.2fs on: %+.2f%% of one core (budget: under 2%% at full load)",
		os.Getenv("OVERHEAD_ONLY"), os.Getenv("OVERHEAD_SCALE"), d, off.Seconds(), on.Seconds(), extra)
}
