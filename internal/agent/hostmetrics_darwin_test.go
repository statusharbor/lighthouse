//go:build darwin

package agent

import (
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// Darwin tests run on macOS only — they call real sysctl + Getfsstat against
// the host. CI on macOS exercises them; other OSes skip via the build tag
// (Linux uses hostmetrics_linux_test.go, the noop fallback covers everything else).

func TestDarwinCollector_EmitsSelfMonitoring(t *testing.T) {
	c := NewLinuxCollector()
	samples, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(samples) < 2 {
		t.Fatalf("at least the two self-monitoring samples should always emit; got %d", len(samples))
	}

	// Only lighthouse_agent_up is emitted now —
	// lighthouse_agent_uptime_seconds was retired, see the matching
	// note in hostmetrics_test.go.
	var sawUp bool
	for _, s := range samples {
		if s.Name == "lighthouse_agent_up" {
			sawUp = true
			if s.Value != 1 {
				t.Errorf("lighthouse_agent_up=%v want 1", s.Value)
			}
		}
		if s.Name == "lighthouse_agent_uptime_seconds" {
			t.Errorf("lighthouse_agent_uptime_seconds was retired; agent should no longer emit it")
		}
	}
	if !sawUp {
		t.Fatal("missing lighthouse_agent_up sample")
	}
}

func TestDarwinCollector_EmitsLoadAvg(t *testing.T) {
	c := NewLinuxCollector()
	samples, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var l1, l5, l15 *transport.HostSample
	for i := range samples {
		switch samples[i].Name {
		case "load1":
			l1 = &samples[i]
		case "load5":
			l5 = &samples[i]
		case "load15":
			l15 = &samples[i]
		}
	}
	if l1 == nil || l5 == nil || l15 == nil {
		t.Fatalf("missing load samples: l1=%v l5=%v l15=%v", l1, l5, l15)
	}
	// Load averages on a running CI machine are non-negative and below 200
	// even on extremely loaded hosts. Generous bound that catches obvious
	// fixed-point math errors (e.g. forgetting fscale would produce ~10^9
	// values).
	for _, s := range []*transport.HostSample{l1, l5, l15} {
		if s.Value < 0 || s.Value > 200 {
			t.Errorf("%s=%v outside plausible range — likely fscale math wrong", s.Name, s.Value)
		}
	}
}

func TestDarwinCollector_EmitsMemoryAndDisk(t *testing.T) {
	c := NewLinuxCollector()
	samples, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var (
		sawMemUsed, sawMemPercent, sawMemAvail bool
		sawDiskUsedPercent                     bool
	)
	for _, s := range samples {
		switch s.Name {
		case "mem_used_bytes":
			sawMemUsed = true
			if s.Value <= 0 {
				t.Errorf("mem_used_bytes=%v should be positive", s.Value)
			}
		case "mem_used_percent":
			sawMemPercent = true
			if s.Value < 0 || s.Value > 100 {
				t.Errorf("mem_used_percent=%v outside [0,100]", s.Value)
			}
		case "mem_available_bytes":
			sawMemAvail = true
		case "disk_used_percent":
			sawDiskUsedPercent = true
			if s.Value < 0 || s.Value > 100 {
				t.Errorf("disk_used_percent=%v outside [0,100] on mount %q", s.Value, s.Labels["mount"])
			}
		}
	}
	if !sawMemUsed || !sawMemPercent || !sawMemAvail {
		t.Fatalf("missing memory samples: used=%v percent=%v avail=%v",
			sawMemUsed, sawMemPercent, sawMemAvail)
	}
	if !sawDiskUsedPercent {
		t.Fatal("no disk_used_percent samples — Getfsstat returned no qualifying mounts")
	}
}

func TestDarwinCollector_MountCardinalityCapped(t *testing.T) {
	c := NewLinuxCollector()
	samples, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	uniqueMounts := map[string]struct{}{}
	for _, s := range samples {
		if s.Name == "disk_used_percent" {
			if m := s.Labels["mount"]; m != "" {
				uniqueMounts[m] = struct{}{}
			}
		}
	}
	if got := len(uniqueMounts); got > maxMountsDarwin {
		t.Errorf("emitted %d mounts; cap is %d — collector ignored maxMountsDarwin", got, maxMountsDarwin)
	}
}

func TestDarwinCollector_EmitsCPUSamples(t *testing.T) {
	// CPU on darwin shells out to /usr/bin/top (kern.cp_time isn't
	// accessible via sysctlbyname and Mach calls would need CGo). Pin the
	// fact that cpu_busy_percent IS emitted so a regression to the
	// "pure-sysctl-and-fail" path is caught here.
	c := NewLinuxCollector()
	samples, _ := c.Collect()
	for _, s := range samples {
		if s.Name == "cpu_busy_percent" {
			return // present, as expected
		}
	}
	t.Fatal("cpu_busy_percent not emitted on darwin — readCPUPercentsDarwin failing silently?")
}

func TestDarwinCollector_FastEnoughForRealTickers(t *testing.T) {
	// Sanity: real production ticker is 30s; collection must be << that.
	// 500ms accommodates the /usr/bin/top fork-exec (~300ms on Apple
	// Silicon) plus the rest of the sysctl + Getfsstat work and still
	// catches genuinely blocking syscalls (e.g. NFS via MNT_WAIT).
	c := NewLinuxCollector()
	start := time.Now()
	_, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("Collect took %s; expected <500ms (slow syscall or NFS-blocked mount?)", d)
	}
}
