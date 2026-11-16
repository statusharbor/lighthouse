//go:build linux && (386 || amd64 || arm64)

package discovery

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf"
	_ "github.com/statusharbor/lighthouse/internal/ebpf/ebpftest"
	"github.com/statusharbor/lighthouse/internal/ebpf/identity"
)

// TestHelperListen is not a test: the kernel test runs this binary again
// with DISCOVERY_HELPER_ADDR set, so the listener belongs to another
// process (the agent ignores its own sockets).
func TestHelperListen(t *testing.T) {
	if dial := os.Getenv("DISCOVERY_HELPER_DIAL"); dial != "" {
		for _, a := range strings.Split(dial, ",") {
			if c, err := net.Dial("tcp", a); err == nil {
				_ = c.Close()
			}
		}
		os.Exit(0)
	}
	addr := os.Getenv("DISCOVERY_HELPER_ADDR")
	if addr == "" {
		t.Skip("helper process only")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Println("error", err)
		os.Exit(1)
	}
	fmt.Println(ln.Addr().(*net.TCPAddr).Port)
	time.Sleep(time.Minute)
	os.Exit(0)
}

func startListener(t *testing.T, addr string) (*exec.Cmd, uint16) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperListen$")
	cmd.Env = append(os.Environ(), "DISCOVERY_HELPER_ADDR="+addr)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	var port uint16
	if _, err := fmt.Fscan(bufio.NewReader(out), &port); err != nil {
		t.Fatalf("helper did not report a port: %v", err)
	}
	return cmd, port
}

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
	s.gauges[name+"|"+l["dst"]+"|"+l["dst_port"]] = v
}

func (s *recSink) gauge(key string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gauges[key]
}
func (s *recSink) Event(kind string, _ time.Time, payload any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, emission{kind, payload.(Listener)})
}

func (s *recSink) wait(t *testing.T, what string, match func(emission) bool) Listener {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		s.mu.Lock()
		for _, e := range s.events {
			if match(e) {
				s.mu.Unlock()
				return e.payload
			}
		}
		if time.Now().After(deadline) {
			for _, e := range s.events {
				t.Logf("%s %+v", e.kind, e.payload)
			}
			s.mu.Unlock()
			t.Fatalf("timed out waiting for %s", what)
		}
		s.mu.Unlock()
	}
}

func port(kind string, p uint16) func(emission) bool {
	return func(e emission) bool { return e.kind == kind && e.payload.Port == p }
}

// On a real kernel (criteria 1 and 2): a listener open before the agent
// starts comes from the snapshot, a new one from the kernel within one
// interval, and a closed one is reported closed within one interval. The
// agent's own listeners are never reported.
func TestDiscovery_Kernel(t *testing.T) {
	ident := identity.New("/proc", identity.NewPodResolver(nil, time.Minute))
	c := New(ident, "/proc")
	if reason, _ := ebpf.Check(c.Requirements(), ebpf.ProbeHost()); reason != "" {
		t.Skipf("eBPF not available here: %s", reason)
	}
	c.Interval = 200 * time.Millisecond

	_, before := startListener(t, "127.0.0.1:0")

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

	// The helper shares our network namespace; it is the host's only when
	// the test runs with host networking.
	ourNS := c.netns(uint32(os.Getpid()))
	l := sink.wait(t, "snapshot listener", port(KindListenerOpen, before))
	if !l.Bootstrap || l.Addr != "127.0.0.1" || l.PID == 0 || l.Exe == "" || l.NetNS != ourNS || l.HostNetwork != (ourNS == c.netns(1)) {
		t.Errorf("snapshot listener: %+v (want netns %d)", l, ourNS)
	}

	// With DISCOVERY_TEST_COMM set, the outer script started a server of
	// that name in another container before this test: it comes from the
	// snapshot with its container and network namespace.
	if comm := os.Getenv("DISCOVERY_TEST_COMM"); comm != "" {
		l := sink.wait(t, comm+" listener", func(e emission) bool { return e.kind == KindListenerOpen && e.payload.Comm == comm })
		if !l.Bootstrap || l.ContainerID == "" || l.NetNS == ourNS ||
			l.Type != "postgresql" || l.Monitor != MonitorPostgres || l.Service != "container:"+l.Exe+":5432" {
			t.Errorf("%s listener: %+v", comm, l)
		}
		t.Logf("%s listener: %+v", comm, l)
	}

	time.Sleep(300 * time.Millisecond) // attached and snapshot taken
	helper, after := startListener(t, "[::]:0")
	l = sink.wait(t, "live listener", port(KindListenerOpen, after))
	if l.Bootstrap || l.Addr != "*" || l.PID != uint32(helper.Process.Pid) || l.Comm == "" {
		t.Errorf("live listener: %+v (want pid %d)", l, helper.Process.Pid)
	}

	// Criterion 5: three connections from another process become one edge
	// with count 3; a refused connect makes none (DSC-U-F7).
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := ln.Addr().String()
	_ = ln.Close()
	target := "127.0.0.1:" + strconv.Itoa(int(after))
	dial := exec.Command(os.Args[0], "-test.run=^TestHelperListen$")
	dial.Env = append(os.Environ(), "DISCOVERY_HELPER_DIAL="+strings.Join([]string{target, target, target, refused}, ","))
	if out, err := dial.CombinedOutput(); err != nil {
		t.Fatalf("dial helper: %v %s", err, out)
	}
	edgeKey := "lighthouse_ebpf_flow_connections_total|127.0.0.1|" + strconv.Itoa(int(after))
	for deadline := time.Now().Add(3 * time.Second); sink.gauge(edgeKey) < 3; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("edge to %s: got %v, want 3 (gauges %v)", target, sink.gauge(edgeKey), sink.gauges)
		}
	}
	if v := sink.gauge(edgeKey); v != 3 {
		t.Errorf("edge count %v, want 3", v)
	}
	_, refusedPort, _ := net.SplitHostPort(refused)
	if v := sink.gauge("lighthouse_ebpf_flow_connections_total|127.0.0.1|" + refusedPort); v != 0 {
		t.Errorf("refused connect made an edge: %v", v)
	}

	_ = helper.Process.Kill()
	_ = helper.Wait()
	sink.wait(t, "closed listener", port(KindListenerClose, after))

	own, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = own.Close() }()
	time.Sleep(600 * time.Millisecond)
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, e := range sink.events {
		if e.payload.Port == uint16(own.Addr().(*net.TCPAddr).Port) {
			t.Errorf("own listener reported: %+v", e)
		}
	}
}
