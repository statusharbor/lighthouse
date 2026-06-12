//go:build windows

// Windows host-metric collector — direct syscalls via x/sys/windows. Pure
// Go (no CGo), no WMI dep. Same dependency posture as Linux and darwin.
//
// What's emitted today (covers ~50% of the curated allowlist):
//   - mem_used_bytes, mem_used_percent, mem_available_bytes
//   - swap_used_bytes, swap_used_percent (page file totals)
//   - per-drive disk_used_bytes, disk_free_bytes, disk_used_percent
//   - lighthouse_agent_up (agent self-monitoring gauge)
//
// What's NOT yet emitted (clearly TODO; design §3.1 allowlist is the contract):
//   - load1, load5, load15 — Windows has no concept of "load average". The
//     closest equivalent is "Processor Queue Length" via Performance
//     Counters; emitting it under load* names would mislead operators
//     (Linux semantics: runnable+uninterruptible processes; Windows PQL:
//     queued threads only). Leave unemitted and document.
//   - cpu_busy/user/system/iowait_percent — GetSystemTimes gives aggregate
//     idle/kernel/user times across all cores; delta-state math like the
//     Linux collector. Pure-Go feasible — left as a focused follow-up.
//   - disk_read/write_bytes_total, disk_io_time_seconds_total — PDH
//     counters (`\PhysicalDisk(_Total)\Disk Bytes/sec` etc.) or
//     IOCTL_DISK_PERFORMANCE; both viable in x/sys/windows but verbose.
//   - net_rx/tx_* — GetIfTable2 via x/sys/windows.
//   - disk_inodes_used_percent — Windows has no inode concept; NTFS MFT
//     "records" are the closest analog but not generally interpretable as
//     a percentage. Stay unemitted (Linux-only metric).
//
// All TODOs are pure-Go feasible — none require CGo or WMI. The agent's
// golden allowlist test still defines the full contract; emitting any of
// the above means lifting the corresponding TODO comment here.

package agent

import (
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// maxMountsWindows mirrors the Linux + darwin cardinality cap (design §3.1).
// Windows logical drives rarely exceed single digits (C:, D:, …), so 26 (the
// full A-Z alphabet) is the natural absolute ceiling; we keep the same 20 cap
// the other collectors use for consistency.
const maxMountsWindows = 20

type windowsCollector struct {
	mu        sync.Mutex
	startedAt time.Time
}

// NewLinuxCollector is the cross-platform entrypoint name (historical — used
// by cmd/lighthouse/main.go on every OS).
func NewLinuxCollector() Collector {
	return &windowsCollector{startedAt: time.Now()}
}

// NewLinuxCollectorWithRoot mirrors the Linux constructor that accepts
// a procfs prefix. Windows has no procfs — the WMI/Performance counter
// collector ignores the argument.
func NewLinuxCollectorWithRoot(_ string) Collector {
	return NewLinuxCollector()
}

// NewLinuxCollectorWithRoots mirrors the Linux constructor that takes both
// procRoot and hostRoot. Windows has neither, so both arguments are
// ignored. Kept so cmd/lighthouse/main.go stays a single line on every
// platform.
func NewLinuxCollectorWithRoots(_, _ string) Collector {
	return NewLinuxCollector()
}

func (c *windowsCollector) Collect() ([]transport.HostSample, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	nowMs := time.Now().UnixMilli()
	out := make([]transport.HostSample, 0, 16)

	// Self-monitoring — emit on every platform regardless. See the Linux
	// collector for the rationale on why uptime_seconds was retired.
	out = append(out,
		transport.HostSample{Name: "lighthouse_agent_up", Value: 1, Timestamp: nowMs},
	)

	// Memory + swap (page file) — single GlobalMemoryStatusEx call.
	if m, err := readMemStatusWindows(); err == nil {
		out = append(out,
			transport.HostSample{Name: "mem_used_bytes", Value: float64(m.usedBytes), Timestamp: nowMs},
			transport.HostSample{Name: "mem_used_percent", Value: m.usedPercent, Timestamp: nowMs},
			transport.HostSample{Name: "mem_available_bytes", Value: float64(m.availableBytes), Timestamp: nowMs},
			transport.HostSample{Name: "swap_used_bytes", Value: float64(m.swapUsedBytes), Timestamp: nowMs},
			transport.HostSample{Name: "swap_used_percent", Value: m.swapUsedPercent, Timestamp: nowMs},
		)
	}

	// Per-drive disk usage — enumerate logical drives via GetLogicalDriveStrings
	// then GetDiskFreeSpaceEx each. Skipped drives (removable, CD/DVD without
	// media) just return an error and are dropped.
	if drives, err := readLogicalDrivesWindows(); err == nil {
		for i, drive := range drives {
			if i >= maxMountsWindows {
				break
			}
			st, err := diskFreeSpaceWindows(drive)
			if err != nil {
				continue
			}
			labels := map[string]string{"mount": drive}
			out = append(out,
				transport.HostSample{Name: "disk_used_bytes", Labels: labels, Value: float64(st.usedBytes), Timestamp: nowMs},
				transport.HostSample{Name: "disk_free_bytes", Labels: labels, Value: float64(st.freeBytes), Timestamp: nowMs},
				transport.HostSample{Name: "disk_used_percent", Labels: labels, Value: st.usedPercent, Timestamp: nowMs},
			)
		}
	}

	return out, nil
}

// --- GlobalMemoryStatusEx -------------------------------------------------

// memoryStatusEx mirrors the MEMORYSTATUSEX struct from sysinfoapi.h. All
// fields are uint64 except dwLength + dwMemoryLoad (uint32). DWORD alignment
// matters — the struct layout below matches the Windows C declaration exactly.
// kernel32 + its procs are looked up once at package init. Doing it inside
// Collect() would mean a symbol lookup per tick — cheap in absolute terms
// but pointless, and noisy under tools that trace syscalls.
var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx  = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetDiskFreeSpaceExW   = kernel32.NewProc("GetDiskFreeSpaceExW")
)

type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

type meminfoWindows struct {
	usedBytes       uint64
	usedPercent     float64
	availableBytes  uint64
	swapUsedBytes   uint64
	swapUsedPercent float64
}

func readMemStatusWindows() (meminfoWindows, error) {
	var ms memoryStatusEx
	ms.dwLength = uint32(unsafe.Sizeof(ms))

	r1, _, lastErr := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	if r1 == 0 {
		return meminfoWindows{}, lastErr
	}

	m := meminfoWindows{availableBytes: ms.ullAvailPhys}
	if ms.ullTotalPhys > ms.ullAvailPhys {
		m.usedBytes = ms.ullTotalPhys - ms.ullAvailPhys
	}
	if ms.ullTotalPhys > 0 {
		m.usedPercent = 100.0 * float64(m.usedBytes) / float64(ms.ullTotalPhys)
	}

	// Page file (Windows' equivalent of swap). ullTotalPageFile includes
	// physical RAM in Microsoft's counting; subtract physical to get the
	// pure page file size, matching what the user sees in Task Manager.
	pageFileTotal := uint64(0)
	if ms.ullTotalPageFile > ms.ullTotalPhys {
		pageFileTotal = ms.ullTotalPageFile - ms.ullTotalPhys
	}
	pageFileAvail := uint64(0)
	if ms.ullAvailPageFile > ms.ullAvailPhys {
		pageFileAvail = ms.ullAvailPageFile - ms.ullAvailPhys
	}
	if pageFileTotal > pageFileAvail {
		m.swapUsedBytes = pageFileTotal - pageFileAvail
	}
	if pageFileTotal > 0 {
		m.swapUsedPercent = 100.0 * float64(m.swapUsedBytes) / float64(pageFileTotal)
	}

	return m, nil
}

// --- GetLogicalDriveStrings ----------------------------------------------

// readLogicalDrivesWindows returns the list of fixed-drive roots ("C:\", "D:\", …).
// Removable drives without media (empty CD slot) are filtered via the second
// pass (diskFreeSpaceWindows returns an error and the caller drops it).
func readLogicalDrivesWindows() ([]string, error) {
	const bufSize = 256
	buf := make([]uint16, bufSize)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buf)-1), &buf[0])
	if err != nil {
		return nil, err
	}
	if n == 0 || n >= uint32(len(buf)) {
		return nil, syscall.ERROR_INSUFFICIENT_BUFFER
	}

	// GetLogicalDriveStrings returns a NUL-separated, double-NUL-terminated
	// list of UTF-16-encoded drive roots. Split on NUL.
	out := []string{}
	start := 0
	for i := uint32(0); i < n; i++ {
		if buf[i] == 0 {
			if i > uint32(start) {
				out = append(out, windows.UTF16ToString(buf[start:i]))
			}
			start = int(i) + 1
		}
	}

	// Filter to fixed drives only — GetDriveType discriminates.
	fixed := out[:0]
	for _, d := range out {
		ptr, err := windows.UTF16PtrFromString(d)
		if err != nil {
			continue
		}
		if windows.GetDriveType(ptr) == windows.DRIVE_FIXED {
			fixed = append(fixed, d)
		}
	}
	return fixed, nil
}

// --- GetDiskFreeSpaceEx ---------------------------------------------------

type fsStatWindows struct {
	usedBytes   uint64
	freeBytes   uint64
	usedPercent float64
}

func diskFreeSpaceWindows(drive string) (fsStatWindows, error) {
	ptr, err := windows.UTF16PtrFromString(drive)
	if err != nil {
		return fsStatWindows{}, err
	}
	var freeAvail, total, totalFree uint64
	// GetDiskFreeSpaceEx — freeAvail = bytes available to caller (respects
	// quotas), totalFree = bytes free on the volume. Use totalFree for our
	// metrics so per-tenant quotas don't skew the numbers.
	r1, _, lastErr := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(ptr)),
		uintptr(unsafe.Pointer(&freeAvail)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r1 == 0 {
		return fsStatWindows{}, lastErr
	}

	fs := fsStatWindows{freeBytes: totalFree}
	if total > totalFree {
		fs.usedBytes = total - totalFree
	}
	if total > 0 {
		fs.usedPercent = 100.0 * float64(fs.usedBytes) / float64(total)
	}
	return fs, nil
}
