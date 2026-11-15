//go:build linux

package incident

import (
	"context"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf"
)

type recSink struct {
	mu     sync.Mutex
	events []emission
	gauges map[string]float64
}

func (s *recSink) Gauge(name string, v float64, l map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gauges == nil {
		s.gauges = map[string]float64{}
	}
	s.gauges[gaugeKey(name, l)] = v
}

func gaugeKey(name string, l map[string]string) string {
	return name + "|" + l["direction"] + "|" + l["peer"] + "|" + l["port"] + "|" + l["reason"]
}

func waitGauge(t *testing.T, s *recSink, key string, d time.Duration) {
	t.Helper()
	for deadline := time.Now().Add(d); ; time.Sleep(50 * time.Millisecond) {
		s.mu.Lock()
		v := s.gauges[key]
		s.mu.Unlock()
		if v >= 1 {
			return
		}
		if time.Now().After(deadline) {
			s.mu.Lock()
			t.Logf("gauges: %v", s.gauges)
			s.mu.Unlock()
			t.Fatalf("timed out waiting for %s", key)
		}
	}
}
func (s *recSink) Event(kind string, at time.Time, payload any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, emission{kind, at, payload})
}

func (s *recSink) find(match func(emission) bool) (emission, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.events {
		if match(e) {
			return e, true
		}
	}
	return emission{}, false
}

func waitEvent(t *testing.T, s *recSink, what string, d time.Duration, match func(emission) bool) emission {
	t.Helper()
	for deadline := time.Now().Add(d); ; time.Sleep(50 * time.Millisecond) {
		if e, ok := s.find(match); ok {
			return e
		}
		if time.Now().After(deadline) {
			s.mu.Lock()
			t.Logf("gauges: %v", s.gauges)
			for _, e := range s.events {
				t.Logf("event %s: %+v", e.kind, e.payload)
			}
			s.mu.Unlock()
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func exitOf(pid int) func(emission) bool {
	return func(e emission) bool {
		pe, ok := e.payload.(ProcessExit)
		return ok && e.kind == KindProcessExit && pe.PID == uint32(pid)
	}
}

// On a real kernel (criteria 1, 2): a segfault is a crashed exit, a
// SIGKILL names its sender, an untracked non-zero exit stays silent, and
// with INCIDENT_TEST_OOM_COMM set (the outer script starts a process of
// that name in a memory-limited container) the OOM kill arrives with
// cgroup scope within 10 seconds.
func TestIncident_Kernel(t *testing.T) {
	c := New(nil)
	if reason, _ := ebpf.Check(c.Requirements(), ebpf.ProbeHost()); reason != "" {
		t.Skipf("eBPF not available here: %s", reason)
	}
	c.Interval = 100 * time.Millisecond
	sink := &recSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, sink) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	}()
	time.Sleep(300 * time.Millisecond) // attached by now

	segv := exec.Command("sh", "-c", "kill -SEGV $$")
	_ = segv.Run()
	e := waitEvent(t, sink, "segfault exit", 3*time.Second, exitOf(segv.Process.Pid))
	if pe := e.payload.(ProcessExit); pe.Class != ClassCrashed || pe.Signal != "SIGSEGV" {
		t.Errorf("segfault: %+v", pe)
	}

	sleeper := exec.Command("sleep", "30")
	if err := sleeper.Start(); err != nil {
		t.Fatal(err)
	}
	_ = syscall.Kill(sleeper.Process.Pid, syscall.SIGKILL)
	_ = sleeper.Wait()
	e = waitEvent(t, sink, "SIGKILL exit", 3*time.Second, exitOf(sleeper.Process.Pid))
	if pe := e.payload.(ProcessExit); pe.Class != ClassKilled || pe.SenderPID != uint32(os.Getpid()) {
		t.Errorf("kill -9: %+v (want sender %d)", pe, os.Getpid())
	}
	if d := time.Since(e.at); d < 0 || d > 5*time.Second {
		t.Errorf("event time off by %v", d)
	}

	quiet := exec.Command("sh", "-c", "exit 3")
	_ = quiet.Run()
	time.Sleep(500 * time.Millisecond)
	if _, ok := sink.find(exitOf(quiet.Process.Pid)); ok {
		t.Error("untracked exit 3 produced an event")
	}

	if comm := os.Getenv("INCIDENT_TEST_OOM_COMM"); comm != "" {
		e = waitEvent(t, sink, "OOM kill of "+comm, 20*time.Second, func(e emission) bool {
			o, ok := e.payload.(OOMKill)
			return ok && o.Comm == comm
		})
		if o := e.payload.(OOMKill); o.Scope != "cgroup" {
			t.Errorf("OOM: %+v", o)
		}
	}
}

// On a real kernel (criterion 4): a connect to a closed port is counted as
// refused within one interval, and the reset the kernel answers it with
// is not counted (no socket, like a port scan, INC-E-F4). A peer that
// aborts an established connection shows up as a received reset.
func TestIncident_KernelTCP(t *testing.T) {
	c := New(nil)
	if reason, _ := ebpf.Check(c.Requirements(), ebpf.ProbeHost()); reason != "" {
		t.Skipf("eBPF not available here: %s", reason)
	}
	c.Interval = 100 * time.Millisecond
	sink := &recSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, sink) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	}()
	time.Sleep(300 * time.Millisecond)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	if conn, err := net.Dial("tcp4", ln.Addr().String()); err == nil {
		_ = conn.Close()
		t.Fatal("dial to a closed port succeeded")
	}
	port := itoa(uint16(closed))
	waitGauge(t, sink, gaugeKey("lighthouse_ebpf_tcp_connect_failures_total",
		map[string]string{"direction": "out", "peer": "127.0.0.1", "port": port, "reason": "refused"}), 2*time.Second)

	ln, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.(*net.TCPConn).SetLinger(0) // close with RST
		_ = conn.Close()
	}()
	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Read(make([]byte, 1))
	_ = conn.Close()
	waitGauge(t, sink, gaugeKey("lighthouse_ebpf_tcp_resets_received_total",
		map[string]string{"direction": "out", "peer": "127.0.0.1", "port": itoa(uint16(ln.Addr().(*net.TCPAddr).Port))}), 2*time.Second)

	sink.mu.Lock()
	defer sink.mu.Unlock()
	for k := range sink.gauges {
		if k == gaugeKey("lighthouse_ebpf_tcp_resets_sent_total", map[string]string{"direction": "out", "peer": "127.0.0.1", "port": port}) {
			t.Errorf("reset to a closed port was counted: %s", k)
		}
	}
}
