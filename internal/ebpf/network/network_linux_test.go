//go:build linux

package network

import (
	"context"
	"fmt"
	"io"
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

// TestHelperDial is not a test: the kernel test runs this binary again with
// NETWORK_HELPER_DIAL=addr,bytes,conns so the connections belong to
// another process (the agent skips its own).
func TestHelperDial(t *testing.T) {
	spec := os.Getenv("NETWORK_HELPER_DIAL")
	if spec == "" {
		t.Skip("helper process only")
	}
	f := strings.Split(spec, ",")
	n, _ := strconv.Atoi(f[1])
	conns, _ := strconv.Atoi(f[2])
	for range conns {
		c, err := net.Dial("tcp", f[0])
		if err != nil {
			fmt.Println("dial:", err)
			os.Exit(1)
		}
		_, _ = c.Write(make([]byte, n))
		_ = c.Close()
	}
	_, _ = net.LookupHost("example.com") // one DNS query through the container's resolver
	os.Exit(0)
}

type recSink struct {
	mu       sync.Mutex
	gauges   map[string]float64
	degraded string
}

func (s *recSink) Gauge(name string, v float64, l map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gauges == nil {
		s.gauges = map[string]float64{}
	}
	s.gauges[name+"|"+l["dst"]+":"+l["dst_port"]+"|"+l["resolver"]] = v
}
func (*recSink) Event(string, time.Time, any) {}
func (s *recSink) Degrade(d string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.degraded = d
}

func (s *recSink) find(prefix string) (float64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.gauges {
		if strings.HasPrefix(k, prefix) {
			return v, true
		}
	}
	return 0, false
}

// On a real kernel (criteria 3, 4 and 6): connections from another process
// to a non-loopback address are counted with their bytes, including ones
// that open and close between iterator passes; connect time is reported;
// a DNS query through the resolver is counted.
func TestNetwork_Kernel(t *testing.T) {
	c := New(identity.New("/proc", identity.NewPodResolver(nil, time.Minute)), "/proc")
	if reason, _ := ebpf.Check(c.Requirements(), ebpf.ProbeHost()); reason != "" {
		t.Skipf("eBPF not available here: %s", reason)
	}
	c.Interval = 300 * time.Millisecond

	var ip net.IP
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && n.IP.IsGlobalUnicast() {
			ip = n.IP
			break
		}
	}
	if ip == nil {
		t.Skip("no non-loopback IPv4 address")
	}
	ln, err := net.Listen("tcp4", ip.String()+":0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, conn); _ = conn.Close() }()
		}
	}()

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
	time.Sleep(500 * time.Millisecond)

	target := ln.Addr().String()
	helper := exec.Command(os.Args[0], "-test.run=^TestHelperDial$")
	helper.Env = append(os.Environ(), "NETWORK_HELPER_DIAL="+target+",200000,5")
	if out, err := helper.CombinedOutput(); err != nil {
		t.Fatalf("helper: %v %s", err, out)
	}

	bytesKey := "lighthouse_ebpf_flow_bytes_sent_total|" + target
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if v, _ := sink.find(bytesKey); v >= 5*200000 {
			break
		}
		if time.Now().After(deadline) {
			sink.mu.Lock()
			t.Fatalf("bytes to %s not counted; degraded=%q gauges=%v", target, sink.degraded, sink.gauges)
		}
	}
	if _, ok := sink.find("lighthouse_ebpf_flow_connect_ms|" + target); !ok {
		t.Error("no connect time")
	}
	if v, ok := sink.find("lighthouse_ebpf_dns_queries_total|"); !ok || v < 1 {
		sink.mu.Lock()
		t.Errorf("no DNS query counted (degraded=%q)", sink.degraded)
		sink.mu.Unlock()
	}
	sink.mu.Lock()
	t.Logf("degraded=%q", sink.degraded)
	sink.mu.Unlock()
}
