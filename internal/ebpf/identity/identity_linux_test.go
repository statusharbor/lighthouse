//go:build linux

package identity

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf"
	_ "github.com/statusharbor/lighthouse/internal/ebpf/ebpftest"
)

type nopSink struct{}

func (nopSink) Gauge(string, float64, map[string]string) {}
func (nopSink) Event(string, time.Time, any)             {}

func procKey(t *testing.T, pid int) Key {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatalf("read stat: %v", err)
	}
	_, start, ok := parseStat(string(b))
	if !ok {
		t.Fatalf("parse stat %q", b)
	}
	return Key{PID: uint32(pid), StartTicks: start}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); !cond(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// On a real kernel: the key built from the kernel's start_boottime equals
// the key built from /proc/<pid>/stat, for a process seeded at startup and
// for one started afterwards, and an exit is recorded. Skipped where eBPF
// is not allowed or the test is not in the host PID namespace.
func TestIdentity_KernelMatchesProc(t *testing.T) {
	c := New("/proc", nil)
	if reason, _ := ebpf.Check(c.Requirements(), ebpf.ProbeHost()); reason != "" {
		t.Skipf("eBPF not available here: %s", reason)
	}
	if err := HostPIDNamespace(); err != nil {
		t.Skip(err)
	}
	c.Interval = 50 * time.Millisecond
	c.Cache = NewCache(0, 1<<16) // swept right after exit

	before := exec.Command("sleep", "30")
	if err := before.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = before.Process.Kill(); _ = before.Wait() }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, nopSink{}) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	}()

	seeded := procKey(t, before.Process.Pid)
	waitFor(t, "seeded process", func() bool { _, ok := c.Cache.Get(seeded); return ok })

	time.Sleep(200 * time.Millisecond) // attached by now
	after := exec.Command("sleep", "30")
	if err := after.Start(); err != nil {
		t.Fatal(err)
	}
	key := procKey(t, after.Process.Pid)
	waitFor(t, "exec event under the /proc key", func() bool { _, ok := c.Cache.Get(key); return ok })
	p, _ := c.Cache.Get(key)
	if p.Comm != "sleep" || p.Exe == "" || p.CgroupID == 0 {
		t.Fatalf("process: %+v", p)
	}

	_ = after.Process.Kill()
	_ = after.Wait()
	waitFor(t, "exit recorded and swept", func() bool { _, ok := c.Cache.Get(key); return !ok })
}

// Criterion 8 against a live runtime: set IDENTITY_TEST_PID to a process
// inside a container and IDENTITY_TEST_CONTAINER_ID to that container's
// full ID (the kernel matrix job and manual runs do; skipped otherwise).
func TestIdentity_ResolvesContainer(t *testing.T) {
	pid, err := strconv.Atoi(os.Getenv("IDENTITY_TEST_PID"))
	want := os.Getenv("IDENTITY_TEST_CONTAINER_ID")
	if err != nil || want == "" {
		t.Skip("IDENTITY_TEST_PID and IDENTITY_TEST_CONTAINER_ID not set")
	}
	c := New("/proc", nil)
	if p := c.describe(context.Background(), uint32(pid)); p.ContainerID != want {
		t.Fatalf("container: got %q, want %q (process %+v)", p.ContainerID, want, p)
	}
}
