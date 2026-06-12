package agent

import (
	"sort"
	"testing"
)

// TestAllowedMetrics_Golden locks the curated allowlist (design §3.1). A
// deliberate addition here means: (1) the per-host series count rose,
// (2) the §4.2 capacity math needs re-running, (3) the
// billing_plans.metrics_max_active_series defaults may need to grow.
// All three of those are policy decisions; do not silently flip this test.
func TestAllowedMetrics_Golden(t *testing.T) {
	want := []string{
		// CPU.
		"cpu_busy_percent",
		"cpu_iowait_percent",
		"cpu_system_percent",
		"cpu_user_percent",

		// Memory + swap.
		"mem_available_bytes",
		"mem_used_bytes",
		"mem_used_percent",
		"swap_used_bytes",
		"swap_used_percent",

		// Load.
		"load1",
		"load15",
		"load5",

		// Per-mount.
		"disk_free_bytes",
		"disk_inodes_used_percent",
		"disk_used_bytes",
		"disk_used_percent",

		// Per-device.
		"disk_io_time_seconds_total",
		"disk_read_bytes_total",
		"disk_write_bytes_total",

		// Per-interface.
		"net_rx_bytes_total",
		"net_rx_errors_total",
		"net_rx_packets_total",
		"net_tx_bytes_total",
		"net_tx_errors_total",
		"net_tx_packets_total",

		// Agent self-monitoring. lighthouse_agent_uptime_seconds was
		// retired — the X-Lighthouse-Process-Uptime request header gives
		// the Console the same signal without burning a series per
		// agent, and the monotonically-growing counter shape was a poor
		// fit for the rule allowlist.
		"lighthouse_agent_up",
	}
	sort.Strings(want)

	got := AllowedMetrics()
	if len(got) != len(want) {
		t.Fatalf("allowlist size changed: got %d, want %d\nadd/remove was deliberate? Update §4.2 capacity math + plan defaults", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("allowlist[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestNoopCollector_EmitsNothing prevents accidentally shipping a no-op as the
// real collector — the integration tests look for actual samples, and Phase 3
// is "wire the contract"; the gopsutil swap is its own follow-up.
func TestNoopCollector_EmitsNothing(t *testing.T) {
	samples, err := NewNoopCollector().Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(samples) != 0 {
		t.Fatalf("noop returned %d samples", len(samples))
	}
}
