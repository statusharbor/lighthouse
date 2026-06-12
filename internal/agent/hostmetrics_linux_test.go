//go:build linux

package agent

import (
	"testing"
	"time"
)

// These tests run only on Linux because the parsers operate on /proc directly.
// CI on Linux exercises them; macOS/Windows skip via the build tag (and the
// noop collector covers the cross-platform contract test).

func TestParseMeminfoLine(t *testing.T) {
	cases := []struct {
		in  string
		key string
		v   uint64
		ok  bool
	}{
		{"MemTotal:        8053220 kB", "MemTotal", 8053220, true},
		{"MemAvailable:    1234567 kB", "MemAvailable", 1234567, true},
		{"SwapTotal:             0 kB", "SwapTotal", 0, true},
		{"garbage no colon", "", 0, false},
		{"NoNumber: not a number kB", "", 0, false},
	}
	for _, c := range cases {
		key, v, ok := parseMeminfoLine(c.in)
		if ok != c.ok || key != c.key || v != c.v {
			t.Errorf("parseMeminfoLine(%q) = (%q,%d,%v) want (%q,%d,%v)", c.in, key, v, ok, c.key, c.v, c.ok)
		}
	}
}

func TestLinuxCollector_EmitsSelfMonitoringOnFirstCall(t *testing.T) {
	c := NewLinuxCollector()
	samples, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// lighthouse_agent_up must always be emitted. The companion
	// lighthouse_agent_uptime_seconds metric was retired — the
	// X-Lighthouse-Process-Uptime header on every request carries the
	// same signal at lower cardinality cost.
	if len(samples) < 1 {
		t.Fatalf("first Collect should emit at least the self-monitoring sample, got %d", len(samples))
	}

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

func TestLinuxCollector_CPUEmittedOnSecondCall(t *testing.T) {
	// First call seeds the prev snapshot; CPU samples appear on the next.
	c := NewLinuxCollector()
	_, _ = c.Collect()

	// Small sleep so /proc/stat moves and the delta is non-zero.
	time.Sleep(10 * time.Millisecond)

	samples, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect (2): %v", err)
	}
	var sawCPU bool
	for _, s := range samples {
		if s.Name == "cpu_busy_percent" {
			sawCPU = true
			if s.Value < 0 || s.Value > 100 {
				t.Errorf("cpu_busy_percent=%v outside [0,100]", s.Value)
			}
		}
	}
	if !sawCPU {
		t.Fatal("second Collect should emit cpu_busy_percent (delta now computable)")
	}
}

func TestReadMounts_DropsPseudoFilesystems(t *testing.T) {
	mounts, err := readMounts(DefaultProcRoot)
	if err != nil {
		t.Fatalf("readMounts: %v", err)
	}
	for _, m := range mounts {
		// proc / sys / cgroup mountpoints should never reach us
		if m == "/proc" || m == "/sys" || m == "/sys/fs/cgroup" {
			t.Errorf("readMounts returned pseudo-fs mountpoint %q", m)
		}
	}
}

func TestStatfsTarget(t *testing.T) {
	cases := []struct {
		name       string
		hostRoot   string
		mountpoint string
		want       string
	}{
		{
			name:       "empty host root preserves mountpoint verbatim",
			hostRoot:   "",
			mountpoint: "/var/lib/docker",
			want:       "/var/lib/docker",
		},
		{
			name:       "non-empty host root prefixes mountpoint",
			hostRoot:   "/host/root",
			mountpoint: "/var/lib/docker",
			want:       "/host/root/var/lib/docker",
		},
		{
			name:       "host root + slash collapses to host root (no trailing slash)",
			hostRoot:   "/host/root",
			mountpoint: "/",
			want:       "/host/root",
		},
		{
			name:       "empty host root + slash returns slash",
			hostRoot:   "",
			mountpoint: "/",
			want:       "/",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := statfsTarget(tc.hostRoot, tc.mountpoint); got != tc.want {
				t.Errorf("statfsTarget(%q, %q) = %q, want %q",
					tc.hostRoot, tc.mountpoint, got, tc.want)
			}
		})
	}
}
