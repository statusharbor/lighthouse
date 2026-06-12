//go:build linux

// Linux host-metric collector — stdlib + /proc + syscall.Statfs only. No
// gopsutil dep on purpose (this agent is public Apache-2.0 and we don't want
// a 1MB dep tree for what is ~300 LOC of /proc parsing).
//
// SCOPE for the first cut (design §3.1 curated allowlist):
//   - CPU aggregate + per-core (uses /proc/stat delta state)
//   - Memory + swap (one /proc/meminfo snapshot per tick)
//   - Load average (/proc/loadavg)
//   - Per-mount filesystem usage (parses /proc/mounts, calls syscall.Statfs)
//   - Agent self-monitoring (lighthouse_agent_up)
//
// Network counters (net_rx_* / net_tx_*) are parsed from /proc/net/dev
// and reported as raw cumulative counters; the Console wraps them in
// rate() server-side to produce throughput. Disk I/O counters
// (disk_read_bytes_total, disk_write_bytes_total,
// disk_io_time_seconds_total) are parsed from /proc/diskstats the same
// way.
package agent

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// linuxCollector implements Collector against /proc. Single instance per
// agent (the runner constructs one in NewLinuxCollector); thread-safe so the
// runner's ticker can call Collect from one goroutine while other code (e.g.
// graceful-shutdown drain) calls it from another.
//
// procRoot is the prefix joined onto "/stat", "/meminfo", etc. — defaults
// to "/proc" for bare-metal but the DaemonSet flavour of the Helm chart
// sets it to "/host/proc" via LIGHTHOUSE_PROC_ROOT so the agent reads
// the node's procfs through a hostPath mount instead of the container's
// own pid-namespace view (which would only see the agent process).
type linuxCollector struct {
	mu        sync.Mutex
	prevCPU   *cpuSnapshot
	startedAt time.Time
	procRoot  string
	// hostRoot, when non-empty, is joined in front of each mountpoint
	// before calling syscall.Statfs. The DaemonSet flavour of the Helm
	// chart bind-mounts the host's / read-only at /host/root and sets
	// this to "/host/root" so per-mount disk stats reflect the node
	// instead of paths that happen to also exist inside the container.
	// Empty (the default) preserves the bare-metal behaviour — Statfs
	// runs on the original mountpoint with no prefix.
	hostRoot string
}

// NewLinuxCollector returns the production Linux collector reading from
// "/proc". Use NewLinuxCollectorWithRoots to override the prefixes —
// DaemonSet pods pass "/host/proc" + (optionally) "/host/root". All three
// constructors exist so the existing bare-metal call sites stay one-line.
func NewLinuxCollector() Collector {
	return NewLinuxCollectorWithRoots(DefaultProcRoot, "")
}

// NewLinuxCollectorWithRoot returns a Linux collector that reads procfs
// from `procRoot` instead of "/proc". Empty falls back to "/proc" so
// callers can pass cfg.Agent.ProcRoot unconditionally. hostRoot stays
// empty — kept as a thin wrapper for backward compatibility with any
// out-of-tree call sites; new code should use NewLinuxCollectorWithRoots.
func NewLinuxCollectorWithRoot(procRoot string) Collector {
	return NewLinuxCollectorWithRoots(procRoot, "")
}

// NewLinuxCollectorWithRoots returns a Linux collector that reads procfs
// from `procRoot` and, when `hostRoot` is non-empty, statfs-prefixes every
// disk mountpoint with it. Empty `procRoot` falls back to "/proc". Empty
// `hostRoot` means "no statfs prefix", matching bare-metal behaviour.
func NewLinuxCollectorWithRoots(procRoot, hostRoot string) Collector {
	if procRoot == "" {
		procRoot = DefaultProcRoot
	}
	return &linuxCollector{
		startedAt: time.Now(),
		procRoot:  procRoot,
		hostRoot:  hostRoot,
	}
}

func (c *linuxCollector) Collect() ([]transport.HostSample, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	nowMs := time.Now().UnixMilli()
	out := make([]transport.HostSample, 0, 64)

	// Agent self-monitoring — single gauge so the dashboard can
	// distinguish "no data" from "agent down". The companion
	// lighthouse_agent_uptime_seconds metric was retired because every
	// real consumer of "did this agent restart" reads the
	// X-Lighthouse-Process-Uptime header on the next request instead,
	// and a monotonically growing counter is a bad shape for the
	// allowlisted rule builder.
	out = append(out,
		transport.HostSample{Name: "lighthouse_agent_up", Value: 1, Timestamp: nowMs},
	)

	// Load average — single fopen, three numbers.
	if l1, l5, l15, err := readLoadAvg(c.procRoot); err == nil {
		out = append(out,
			transport.HostSample{Name: "load1", Value: l1, Timestamp: nowMs},
			transport.HostSample{Name: "load5", Value: l5, Timestamp: nowMs},
			transport.HostSample{Name: "load15", Value: l15, Timestamp: nowMs},
		)
	}

	// Memory + swap.
	if m, err := readMeminfo(c.procRoot); err == nil {
		out = append(out,
			transport.HostSample{Name: "mem_used_bytes", Value: float64(m.usedBytes), Timestamp: nowMs},
			transport.HostSample{Name: "mem_used_percent", Value: m.usedPercent, Timestamp: nowMs},
			transport.HostSample{Name: "mem_available_bytes", Value: float64(m.availableBytes), Timestamp: nowMs},
			transport.HostSample{Name: "swap_used_bytes", Value: float64(m.swapUsedBytes), Timestamp: nowMs},
			transport.HostSample{Name: "swap_used_percent", Value: m.swapUsedPercent, Timestamp: nowMs},
		)
	}

	// CPU — delta against prev snapshot. First tick emits nothing for CPU
	// (no prev → can't compute a rate); the second tick onwards is real.
	if snap, err := readCPUSnapshot(c.procRoot); err == nil {
		if c.prevCPU != nil {
			deltas := cpuDeltas(c.prevCPU, snap)
			for _, d := range deltas {
				out = append(out,
					transport.HostSample{Name: "cpu_busy_percent", Labels: d.labels, Value: d.busy, Timestamp: nowMs},
					transport.HostSample{Name: "cpu_user_percent", Labels: d.labels, Value: d.user, Timestamp: nowMs},
					transport.HostSample{Name: "cpu_system_percent", Labels: d.labels, Value: d.system, Timestamp: nowMs},
					transport.HostSample{Name: "cpu_iowait_percent", Labels: d.labels, Value: d.iowait, Timestamp: nowMs},
				)
			}
		}
		c.prevCPU = snap
	}

	// Per-device disk I/O counters from /proc/diskstats. Emitted as raw
	// cumulative counters (sectors × 512 for bytes; ms / 1000 for the
	// io_time fraction); the Console runs rate() server-side to produce
	// throughput. Capped at maxDiskDevices and filtered to whole disks
	// only — partitions, loop/ram/zram/dm devices, and the like are noise
	// on a host-metrics dashboard and would blow the per-team cardinality
	// budget on container hosts.
	if disks, err := readDiskstats(c.procRoot); err == nil {
		for i, d := range disks {
			if i >= maxDiskDevices {
				break
			}
			labels := map[string]string{"device": d.device}
			out = append(out,
				transport.HostSample{Name: "disk_read_bytes_total", Labels: labels, Value: float64(d.readBytes), Timestamp: nowMs},
				transport.HostSample{Name: "disk_write_bytes_total", Labels: labels, Value: float64(d.writeBytes), Timestamp: nowMs},
				// ioTimeMs / 1000 → seconds. The Console renders rate() of
				// this as the "I/O busy fraction" (0..1 of wall-clock).
				transport.HostSample{Name: "disk_io_time_seconds_total", Labels: labels, Value: float64(d.ioTimeMs) / 1000.0, Timestamp: nowMs},
			)
		}
	}

	// Per-interface network counters. Emitted as raw cumulative counters
	// (the Console runs rate() server-side to produce throughput). Cap at
	// maxNetInterfaces so a Docker host with hundreds of veth/cni/br-*
	// virtual interfaces can't blow the cardinality budget. The skip set
	// in readNetDev drops loopback + the usual virtual-interface families;
	// anything that gets past that and a maxNetInterfaces-deep truncation
	// is rare enough to not worry about.
	if nets, err := readNetDev(c.procRoot); err == nil {
		for i, ns := range nets {
			if i >= maxNetInterfaces {
				break
			}
			labels := map[string]string{"device": ns.iface}
			out = append(out,
				transport.HostSample{Name: "net_rx_bytes_total", Labels: labels, Value: float64(ns.rxBytes), Timestamp: nowMs},
				transport.HostSample{Name: "net_tx_bytes_total", Labels: labels, Value: float64(ns.txBytes), Timestamp: nowMs},
				transport.HostSample{Name: "net_rx_packets_total", Labels: labels, Value: float64(ns.rxPackets), Timestamp: nowMs},
				transport.HostSample{Name: "net_tx_packets_total", Labels: labels, Value: float64(ns.txPackets), Timestamp: nowMs},
				transport.HostSample{Name: "net_rx_errors_total", Labels: labels, Value: float64(ns.rxErrors), Timestamp: nowMs},
				transport.HostSample{Name: "net_tx_errors_total", Labels: labels, Value: float64(ns.txErrors), Timestamp: nowMs},
			)
		}
	}

	// Per-mount disk usage. Bound to MAX_MOUNTS so a container-rich host with
	// thousands of bind-mounts can't blow the cardinality cap (design §3.1).
	//
	// statfs runs on the path resolved through c.hostRoot — see
	// statfsTarget for the rules. The metric label "mount" stays the
	// unprefixed host path so dashboards keep showing "/var/lib/docker"
	// rather than "/host/root/var/lib/docker".
	if mounts, err := readMounts(c.procRoot); err == nil {
		for i, mp := range mounts {
			if i >= maxMounts {
				break
			}
			st, err := statfs(statfsTarget(c.hostRoot, mp))
			if err != nil {
				continue
			}
			labels := map[string]string{"mount": mp}
			out = append(out,
				transport.HostSample{Name: "disk_used_bytes", Labels: labels, Value: float64(st.usedBytes), Timestamp: nowMs},
				transport.HostSample{Name: "disk_free_bytes", Labels: labels, Value: float64(st.freeBytes), Timestamp: nowMs},
				transport.HostSample{Name: "disk_used_percent", Labels: labels, Value: st.usedPercent, Timestamp: nowMs},
				transport.HostSample{Name: "disk_inodes_used_percent", Labels: labels, Value: st.inodesUsedPercent, Timestamp: nowMs},
			)
		}
	}

	return out, nil
}

// maxMounts caps per-host mount cardinality (design §3.1 "bound mount/interface
// counts"). 20 is plenty for non-container hosts and keeps containerised hosts
// from running away.
const maxMounts = 20

// maxNetInterfaces mirrors the Darwin collector's cap (hostmetrics_darwin.go).
// A typical Linux host has ~5 real interfaces (eth0/wlan0 + loopback +
// maybe a docker0 bridge); 16 absorbs VPN tunnels and a few veth pairs
// without inviting Docker hosts with hundreds of pods to blow the
// per-team cardinality budget.
const maxNetInterfaces = 16

// maxDiskDevices caps per-host disk-stat cardinality (same reasoning as
// maxNetInterfaces / maxMounts). A typical bare-metal host has ~3 whole
// disks (root + maybe a couple of spinners); 8 leaves room for an NVMe
// rig and any RAID/dm devices that pass the isWholeDiskName filter.
const maxDiskDevices = 8

// skippedNetIfacePrefixes is the virtual-interface family allow-skip list
// consulted by skipNetInterface on every /proc/net/dev line. Lifted to a
// package-level var so we don't re-allocate the slice on every collector
// tick — Go's compiler can't hoist a composite literal out of a function
// body, so an inline literal would cost a few allocations per tick.
//
// Coverage:
//   - docker / br- / veth          — Docker bridge + CNI plumbing.
//   - cni / flannel / cali / weave / cilium — Kubernetes overlay networking.
//   - virbr / vnet                  — libvirt / KVM bridges.
//   - tap / tun                     — generic virtual interfaces. On Linux
//                                     these are noise (real VPN traffic
//                                     comes via the underlying eth/wlan
//                                     and shows up there anyway).
//
// Loopback ("lo") is handled separately because it's exact-match, not a
// prefix — `lo0` could conceivably show up via some alias plumbing.
var skippedNetIfacePrefixes = []string{
	"docker", "br-", "veth",
	"cni", "flannel", "cali", "weave", "cilium",
	"virbr", "vnet",
	"tap", "tun",
}

// --- /proc/loadavg ---------------------------------------------------------

func readLoadAvg(procRoot string) (float64, float64, float64, error) {
	b, err := os.ReadFile(filepath.Join(procRoot, "loadavg"))
	if err != nil {
		return 0, 0, 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return 0, 0, 0, errBadProc("loadavg")
	}
	l1, _ := strconv.ParseFloat(fields[0], 64)
	l5, _ := strconv.ParseFloat(fields[1], 64)
	l15, _ := strconv.ParseFloat(fields[2], 64)
	return l1, l5, l15, nil
}

// --- /proc/meminfo ---------------------------------------------------------

type meminfo struct {
	usedBytes       uint64
	usedPercent     float64
	availableBytes  uint64
	swapUsedBytes   uint64
	swapUsedPercent float64
}

func readMeminfo(procRoot string) (meminfo, error) {
	f, err := os.Open(filepath.Join(procRoot, "meminfo"))
	if err != nil {
		return meminfo{}, err
	}
	defer f.Close()

	var total, available, swapTotal, swapFree uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		key, vKb, ok := parseMeminfoLine(line)
		if !ok {
			continue
		}
		switch key {
		case "MemTotal":
			total = vKb * 1024
		case "MemAvailable":
			available = vKb * 1024
		case "SwapTotal":
			swapTotal = vKb * 1024
		case "SwapFree":
			swapFree = vKb * 1024
		}
	}
	m := meminfo{availableBytes: available}
	if total > 0 {
		m.usedBytes = total - available
		m.usedPercent = 100.0 * float64(m.usedBytes) / float64(total)
	}
	if swapTotal > 0 {
		m.swapUsedBytes = swapTotal - swapFree
		m.swapUsedPercent = 100.0 * float64(m.swapUsedBytes) / float64(swapTotal)
	}
	return m, nil
}

func parseMeminfoLine(line string) (string, uint64, bool) {
	// Lines look like "MemTotal:        8053220 kB".
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return "", 0, false
	}
	key := line[:colon]
	rest := strings.TrimSpace(line[colon+1:])
	// strip the "kB" suffix Linux always emits.
	rest = strings.TrimSuffix(rest, " kB")
	v, err := strconv.ParseUint(strings.TrimSpace(rest), 10, 64)
	if err != nil {
		return "", 0, false
	}
	return key, v, true
}

// --- /proc/stat (CPU) ------------------------------------------------------

type cpuSnapshot struct {
	at      time.Time
	total   []cpuTimes // index 0 = aggregate, 1..N = per-core
}

type cpuTimes struct {
	label  string // "" for aggregate; "0", "1", … for per-core
	user, nice, system, idle, iowait, irq, softirq, steal uint64
}

func readCPUSnapshot(procRoot string) (*cpuSnapshot, error) {
	f, err := os.Open(filepath.Join(procRoot, "stat"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	snap := &cpuSnapshot{at: time.Now()}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		var label string
		if fields[0] != "cpu" {
			label = strings.TrimPrefix(fields[0], "cpu")
		}
		t := cpuTimes{label: label}
		t.user, _ = strconv.ParseUint(fields[1], 10, 64)
		t.nice, _ = strconv.ParseUint(fields[2], 10, 64)
		t.system, _ = strconv.ParseUint(fields[3], 10, 64)
		t.idle, _ = strconv.ParseUint(fields[4], 10, 64)
		t.iowait, _ = strconv.ParseUint(fields[5], 10, 64)
		t.irq, _ = strconv.ParseUint(fields[6], 10, 64)
		t.softirq, _ = strconv.ParseUint(fields[7], 10, 64)
		if len(fields) >= 9 {
			t.steal, _ = strconv.ParseUint(fields[8], 10, 64)
		}
		snap.total = append(snap.total, t)
	}
	return snap, sc.Err()
}

type cpuDelta struct {
	labels map[string]string
	busy, user, system, iowait float64
}

func cpuDeltas(prev, cur *cpuSnapshot) []cpuDelta {
	if prev == nil || cur == nil {
		return nil
	}
	out := make([]cpuDelta, 0, len(cur.total))
	// align by index — both snapshots iterate /proc/stat top-down so order is stable
	n := len(prev.total)
	if len(cur.total) < n {
		n = len(cur.total)
	}
	for i := 0; i < n; i++ {
		p, c := prev.total[i], cur.total[i]
		var labels map[string]string
		if c.label != "" {
			labels = map[string]string{"core": c.label}
		}
		totalDelta := float64((c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + c.steal) -
			(p.user + p.nice + p.system + p.idle + p.iowait + p.irq + p.softirq + p.steal))
		if totalDelta <= 0 {
			continue
		}
		idleDelta := float64(c.idle - p.idle)
		out = append(out, cpuDelta{
			labels: labels,
			busy:   100.0 * (totalDelta - idleDelta) / totalDelta,
			user:   100.0 * float64(c.user-p.user) / totalDelta,
			system: 100.0 * float64(c.system-p.system) / totalDelta,
			iowait: 100.0 * float64(c.iowait-p.iowait) / totalDelta,
		})
	}
	return out
}

// --- /proc/mounts + statfs -------------------------------------------------

// readMounts returns the set of mountpoints we should report on. Filters:
//   - skip pseudo filesystems (proc, sysfs, cgroup, …)
//   - skip read-only mounts (e.g. snap squashfs)
//   - dedup by mountpoint (some pseudo-fs appear twice)
func readMounts(procRoot string) ([]string, error) {
	f, err := os.Open(filepath.Join(procRoot, "mounts"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	skip := map[string]struct{}{
		"proc": {}, "sysfs": {}, "cgroup": {}, "cgroup2": {}, "devpts": {},
		"devtmpfs": {}, "tmpfs": {}, "debugfs": {}, "tracefs": {}, "mqueue": {},
		"securityfs": {}, "pstore": {}, "configfs": {}, "fusectl": {},
		"hugetlbfs": {}, "autofs": {}, "binfmt_misc": {}, "rpc_pipefs": {},
		"overlay": {}, "squashfs": {}, "ramfs": {}, "nsfs": {}, "fuse.snapfuse": {},
	}
	seen := make(map[string]struct{}, 16)
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		mountpoint, fstype, opts := fields[1], fields[2], fields[3]
		if _, ok := skip[fstype]; ok {
			continue
		}
		if strings.HasPrefix(opts, "ro,") || opts == "ro" || strings.Contains(opts, ",ro,") || strings.HasSuffix(opts, ",ro") {
			continue
		}
		if _, ok := seen[mountpoint]; ok {
			continue
		}
		seen[mountpoint] = struct{}{}
		out = append(out, mountpoint)
	}
	return out, sc.Err()
}

type fsStats struct {
	usedBytes         uint64
	freeBytes         uint64
	usedPercent       float64
	inodesUsedPercent float64
}

// statfsTarget joins hostRoot in front of mountpoint when hostRoot is
// non-empty, returning a path Statfs can resolve through the pod's mount
// namespace into the real host filesystem. Empty hostRoot returns the
// mountpoint unchanged so bare-metal callers don't pay for a path join.
// Mountpoint "/" combined with a hostRoot like "/host/root" must resolve
// to "/host/root" (not "/host/root/"), which filepath.Join handles by
// cleaning the result.
func statfsTarget(hostRoot, mountpoint string) string {
	if hostRoot == "" {
		return mountpoint
	}
	return filepath.Join(hostRoot, mountpoint)
}

func statfs(mountpoint string) (fsStats, error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(mountpoint, &s); err != nil {
		return fsStats{}, err
	}
	totalBytes := s.Blocks * uint64(s.Bsize)
	freeBytes := s.Bavail * uint64(s.Bsize)
	used := totalBytes - freeBytes
	out := fsStats{usedBytes: used, freeBytes: freeBytes}
	if totalBytes > 0 {
		out.usedPercent = 100.0 * float64(used) / float64(totalBytes)
	}
	if s.Files > 0 {
		out.inodesUsedPercent = 100.0 * float64(s.Files-s.Ffree) / float64(s.Files)
	}
	return out, nil
}

// --- /proc/net/dev ---------------------------------------------------------

// netStats is one interface's counters; all six are cumulative since boot.
// The collector emits raw values (the Console runs rate() server-side), so
// we don't carry a prev-snapshot like CPU does — every tick is independent.
type netStats struct {
	iface                string
	rxBytes, rxPackets   uint64
	rxErrors             uint64
	txBytes, txPackets   uint64
	txErrors             uint64
}

// readNetDev parses /proc/net/dev and returns one entry per non-skipped
// interface. Skip set covers loopback + every common virtual-interface
// family (docker, kubernetes, libvirt, etc.) so a container host doesn't
// flood the chart with veth pairs that share lifetime with whatever pod
// created them — fine grained per-pod traffic is not what a host-metrics
// dashboard is for. Stable lexicographic ordering keeps the cap deterministic
// across ticks.
func readNetDev(procRoot string) ([]netStats, error) {
	f, err := os.Open(filepath.Join(procRoot, "net", "dev"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make([]netStats, 0, 8)
	sc := bufio.NewScanner(f)
	// Two header lines.
	for i := 0; i < 2; i++ {
		if !sc.Scan() {
			return nil, sc.Err()
		}
	}
	for sc.Scan() {
		line := sc.Text()
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:colon])
		if skipNetInterface(iface) {
			continue
		}
		// 16 numeric fields after the colon. We need indices 0,1,2 (rx
		// bytes/packets/errs) and 8,9,10 (tx bytes/packets/errs).
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 16 {
			continue
		}
		rxBytes, _ := strconv.ParseUint(fields[0], 10, 64)
		rxPackets, _ := strconv.ParseUint(fields[1], 10, 64)
		rxErrs, _ := strconv.ParseUint(fields[2], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[8], 10, 64)
		txPackets, _ := strconv.ParseUint(fields[9], 10, 64)
		txErrs, _ := strconv.ParseUint(fields[10], 10, 64)
		out = append(out, netStats{
			iface:     iface,
			rxBytes:   rxBytes,
			rxPackets: rxPackets,
			rxErrors:  rxErrs,
			txBytes:   txBytes,
			txPackets: txPackets,
			txErrors:  txErrs,
		})
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	// Sort by name so the maxNetInterfaces cap picks the same interfaces
	// every tick. Without this, /proc ordering can shift across reboots
	// (especially after udev rename) and a host that legitimately exceeds
	// the cap would see its chart series swap mid-flight.
	sortStringy(out)
	return out, nil
}

// skipNetInterface filters out loopback and virtual-interface families that
// are noise on a host-metrics dashboard:
//
//   - lo                      — loopback; rx/tx always equal, never useful.
//   - docker* / br-* / veth*  — Docker/CNI plumbing.
//   - cni* / flannel* / cali* / weave* / cilium* — k8s overlay networking.
//   - virbr* / vnet*          — libvirt / KVM bridges.
//   - tap* / tun*             — generic virtual interfaces (preserve utun-
//                               style VPN names via the explicit "utun"
//                               check; on Linux those carry real user
//                               traffic).
//
// Edge case: leaves real interfaces like eth0, wlan0, enp0s3, wlp3s0 alone.
// If you have a USB-eth dongle that comes up as a tap-shaped name, it would
// be filtered — accepted tradeoff to keep container hosts from drowning the
// dashboard in ephemeral interfaces.
func skipNetInterface(iface string) bool {
	if iface == "lo" {
		return true
	}
	for _, p := range skippedNetIfacePrefixes {
		if strings.HasPrefix(iface, p) {
			return true
		}
	}
	return false
}

// sortStringy sorts netStats by iface name. Stable lexicographic order so
// that under the cap the same interfaces are kept every tick.
func sortStringy(s []netStats) {
	sort.Slice(s, func(i, j int) bool { return s[i].iface < s[j].iface })
}

// --- /proc/diskstats -------------------------------------------------------

// diskIOStats is one device's counters; emitted as raw cumulative counters
// (no rate-of-change carried across ticks here — the Console runs rate()
// server-side, same as net_*_total).
type diskIOStats struct {
	device     string
	readBytes  uint64 // sectorsRead × 512 (the kernel's accounting sector size)
	writeBytes uint64 // sectorsWritten × 512
	ioTimeMs   uint64 // milliseconds the device spent doing I/O
}

// readDiskstats parses /proc/diskstats. Field layout per the kernel docs
// (Documentation/iostats.txt — stable since 4.18 when discard counters were
// added; we only consume the historical 14 we need):
//
//	1  major     2 minor     3 device name
//	4  reads_completed     5 reads_merged     6 sectors_read     7 ms_reading
//	8  writes_completed    9 writes_merged   10 sectors_written 11 ms_writing
//	12 ios_in_progress    13 ms_doing_io     14 weighted_ms_doing_io
//
// We use 6, 10, 13. Sectors are always 512 bytes in this file (kernel
// accounting size; doesn't follow the actual hardware sector size).
func readDiskstats(procRoot string) ([]diskIOStats, error) {
	f, err := os.Open(filepath.Join(procRoot, "diskstats"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make([]diskIOStats, 0, 4)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 14 {
			continue
		}
		name := fields[2]
		if !isWholeDiskName(name) {
			continue
		}
		sectorsRead, _ := strconv.ParseUint(fields[5], 10, 64)
		sectorsWritten, _ := strconv.ParseUint(fields[9], 10, 64)
		msDoingIO, _ := strconv.ParseUint(fields[12], 10, 64)
		out = append(out, diskIOStats{
			device:     name,
			readBytes:  sectorsRead * 512,
			writeBytes: sectorsWritten * 512,
			ioTimeMs:   msDoingIO,
		})
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	// Stable name ordering so the cap picks the same devices every tick.
	sortDiskstats(out)
	return out, nil
}

// isWholeDiskName picks only "whole disk" device names — sda, vda, nvme0n1,
// mmcblk0, md0 — and rejects partitions (sda1, nvme0n1p1, mmcblk0p1),
// loop/ram/zram/sr devices, and device-mapper layers. The dashboard cares
// about physical I/O attribution, not "the partition that happens to host
// /var" (the per-mount usage chart already covers that angle).
func isWholeDiskName(name string) bool {
	switch {
	case len(name) < 3:
		return false
	case strings.HasPrefix(name, "nvme"):
		// nvme<digits>n<digits>, no trailing partition suffix.
		rest := name[4:]
		nIdx := strings.Index(rest, "n")
		if nIdx <= 0 {
			return false
		}
		return allDigits(rest[:nIdx]) && allDigits(rest[nIdx+1:])
	case strings.HasPrefix(name, "mmcblk"):
		return allDigits(name[6:])
	case strings.HasPrefix(name, "md"):
		return allDigits(name[2:])
	}
	// Traditional SCSI/IDE/Xen/virtio whole disks: letter-only suffix
	// after the prefix. sda, vda, hda, xvda → whole; sda1 → partition,
	// rejected because '1' is not in [a-z].
	for _, prefix := range []string{"sd", "vd", "hd", "xvd"} {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		rest := name[len(prefix):]
		if rest == "" {
			return false
		}
		for _, c := range rest {
			if c < 'a' || c > 'z' {
				return false
			}
		}
		return true
	}
	return false
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// sortDiskstats orders devices by name so the cap picks a stable subset.
func sortDiskstats(s []diskIOStats) {
	sort.Slice(s, func(i, j int) bool { return s[i].device < s[j].device })
}

// --- tiny error helper -----------------------------------------------------

type badProcError string

func (e badProcError) Error() string { return "lighthouse: bad /proc/" + string(e) + " line" }
func errBadProc(name string) error   { return badProcError(name) }
