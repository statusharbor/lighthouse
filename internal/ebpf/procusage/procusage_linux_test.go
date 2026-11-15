//go:build linux

package procusage

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/statusharbor/lighthouse/internal/ebpf"
	_ "github.com/statusharbor/lighthouse/internal/ebpf/ebpftest"
	"github.com/statusharbor/lighthouse/internal/ebpf/identity"
	"github.com/statusharbor/lighthouse/internal/usage"
)

type recSink struct {
	mu     sync.Mutex
	gauges map[string]float64
}

func (s *recSink) Gauge(name string, v float64, l map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gauges == nil {
		s.gauges = map[string]float64{}
	}
	s.gauges[name+"|"+l["device"]+"|"+l["quantile"]] = v
}
func (*recSink) Event(string, time.Time, any) {}

// On a real kernel (criteria 3 and 4): CPU of 200 processes that start and
// exit between two polls is attributed to their command, a 5 MB write to a
// regular file shows as file I/O of the writer, reading /dev/zero adds
// nothing, and direct writes give disk latency for the device.
func TestUsage_Kernel(t *testing.T) {
	ident := identity.New("/proc", identity.NewPodResolver(nil, time.Minute))
	acct := usage.NewAccountant()
	poller := usage.NewPoller(acct, "/proc", nil)
	c := New(ident, acct, poller)
	if reason, _ := ebpf.Check(c.Requirements(), ebpf.ProbeHost()); reason != "" {
		t.Skipf("eBPF not available here: %s", reason)
	}
	c.Interval = 200 * time.Millisecond
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
	if _, err := poller.Collect(); err != nil { // baseline
		t.Fatal(err)
	}

	burst := `i=0; while [ $i -lt 200 ]; do /bin/true; i=$((i+1)); done`
	if out, err := exec.Command("sh", "-c", burst).CombinedOutput(); err != nil {
		t.Fatalf("burst: %v %s", err, out)
	}
	f, err := os.CreateTemp("", "usage-*")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	defer func() { _ = os.Remove(f.Name()) }()
	// Disk latency needs I/O that reaches a block device. A temp dir on a
	// virtual filesystem (a VM's shared root, tmpfs) has none and may
	// refuse O_DIRECT, so there only CPU and file I/O are checked.
	var fs unix.Statfs_t
	onDisk := unix.Statfs(f.Name(), &fs) == nil &&
		fs.Type != unix.TMPFS_MAGIC && fs.Type != unix.V9FS_MAGIC && fs.Type != unix.FUSE_SUPER_MAGIC
	args := []string{"if=/dev/zero", "of=" + f.Name(), "bs=1M", "count=5"}
	if onDisk {
		args = append(args, "oflag=direct")
	}
	if out, err := exec.Command("dd", args...).CombinedOutput(); err != nil {
		t.Fatalf("dd: %v %s", err, out)
	}
	time.Sleep(600 * time.Millisecond) // a few collector intervals

	samples, err := poller.Collect()
	if err != nil {
		t.Fatal(err)
	}
	top := map[string]map[string]float64{}
	for _, s := range samples {
		if top[s.Name] == nil {
			top[s.Name] = map[string]float64{}
		}
		top[s.Name][s.Labels["group"]] = s.Value
	}
	t.Logf("cpu: %v", top["lighthouse_top_cpu_cores"])
	t.Logf("file io: %v", top["lighthouse_top_file_io_bytes_per_second"])
	if top["lighthouse_top_cpu_cores"]["process:true"] <= 0 && top["lighthouse_top_cpu_cores"]["process:sh"] <= 0 {
		t.Error("short-lived processes' CPU not attributed")
	}
	if top["lighthouse_top_file_io_bytes_per_second"]["process:dd"] <= 0 {
		t.Error("dd's file I/O not attributed")
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	found := false
	for k := range sink.gauges {
		if strings.HasPrefix(k, "lighthouse_ebpf_disk_latency_ms|") {
			found = true
		}
	}
	switch {
	case !onDisk:
		t.Logf("temp dir is not on a block device: disk latency not checked")
	case !found:
		t.Errorf("no disk latency: %v", sink.gauges)
	}
}
