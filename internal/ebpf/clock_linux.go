//go:build linux

package ebpf

import (
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// WallTime converts a bpf_ktime_get_boot_ns timestamp to wall-clock time.
// It reads both clocks on every call (two vDSO calls), so there is no
// cached offset to go stale.
func WallTime(bootNS uint64) time.Time {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts) != nil {
		return time.Now()
	}
	return wallFromBoot(bootNS, uint64(ts.Nano()), time.Now())
}

// BootID identifies the current kernel boot; kernel timestamps are only
// comparable within one boot. Containers see the host's value.
func BootID() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}
