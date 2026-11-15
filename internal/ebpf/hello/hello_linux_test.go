//go:build linux

package hello

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf"
	_ "github.com/statusharbor/lighthouse/internal/ebpf/ebpftest"
)

type gaugeSink struct {
	mu   sync.Mutex
	last float64
	n    int
}

func (s *gaugeSink) Gauge(_ string, v float64, _ map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last, s.n = v, s.n+1
}
func (*gaugeSink) Event(string, time.Time, any) {}

// FND-E-P1 in miniature: on a host where eBPF is allowed the hello
// collector loads, counts exec calls and reports them. Skipped where the
// test process may not load programs (normal CI runners, laptops).
func TestHello_CountsExecs(t *testing.T) {
	if reason, _ := ebpf.Check(New().Requirements(), ebpf.ProbeHost()); reason != "" {
		t.Skipf("eBPF not available here: %s", reason)
	}
	c := &Collector{Interval: 200 * time.Millisecond}
	sink := &gaugeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, sink) }()

	time.Sleep(300 * time.Millisecond) // attached by now
	for range 5 {
		_ = exec.Command(os.Args[0], "-test.run=^$").Run()
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		sink.mu.Lock()
		got := sink.last
		sink.mu.Unlock()
		if got >= 5 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sink.last < 5 {
		t.Fatalf("exec count: got %v, want >= 5", sink.last)
	}
}
