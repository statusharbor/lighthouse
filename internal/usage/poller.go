package usage

import (
	"bufio"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// procStat is the part of /proc/<pid>/stat the poller reads.
type procStat struct {
	comm         string
	kernelThread bool
	cpuTicks     uint64 // utime + stime
	startTicks   uint64
	rssPages     uint64
}

const pfKthread = 0x00200000

// parseProcStat parses /proc/<pid>/stat. The command sits in parentheses
// and may hold spaces or ")", so fields are counted after the last ")".
func parseProcStat(s string) (procStat, bool) {
	open, end := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || end < open {
		return procStat{}, false
	}
	f := strings.Fields(s[end+1:])
	// f[0] is field 3 (state); utime 14, stime 15, starttime 22, rss 24.
	if len(f) < 22 {
		return procStat{}, false
	}
	num := func(i int) uint64 { n, _ := strconv.ParseUint(f[i-3], 10, 64); return n }
	return procStat{
		comm:         s[open+1 : end],
		kernelThread: num(9)&pfKthread != 0,
		cpuTicks:     num(14) + num(15),
		startTicks:   num(22),
		rssPages:     num(24),
	}, true
}

// hostBusyTicks returns busy and total jiffies from /proc/stat's cpu line.
func hostBusyTicks(r io.Reader) (busy, total uint64) {
	sc := bufio.NewScanner(r)
	if !sc.Scan() {
		return 0, 0
	}
	f := strings.Fields(sc.Text())
	if len(f) < 6 || f[0] != "cpu" {
		return 0, 0
	}
	for i, v := range f[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		total += n
		if i != 3 && i != 4 { // idle, iowait
			busy += n
		}
	}
	return busy, total
}

// ioStatBytes sums rbytes and wbytes over the devices of a cgroup io.stat.
func ioStatBytes(r io.Reader) uint64 {
	var sum uint64
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		for _, kv := range strings.Fields(sc.Text())[1:] {
			if k, v, ok := strings.Cut(kv, "="); ok && (k == "rbytes" || k == "wbytes") {
				n, _ := strconv.ParseUint(v, 10, 64)
				sum += n
			}
		}
	}
	return sum
}

// samples turns one interval into the top-N gauges, plus "other". CPU's
// "other" includes what the kernel spent outside any process (hostCores).
func samples(iv Interval, device map[string]float64, hostCores float64, now time.Time) []transport.HostSample {
	ts := now.UnixMilli()
	var out []transport.HostSample
	add := func(name string, values map[string]float64, total float64) {
		for _, e := range Top(values, total) {
			out = append(out, transport.HostSample{Name: name, Labels: map[string]string{"group": e.Group}, Value: e.Value, Timestamp: ts})
		}
	}
	add("lighthouse_top_cpu_cores", iv.CPU, hostCores)
	add("lighthouse_top_memory_bytes", iv.Memory, 0)
	add("lighthouse_top_file_io_bytes_per_second", iv.FileIO, 0)
	add("lighthouse_top_device_io_bytes_per_second", device, 0)
	add("lighthouse_top_network_bytes_per_second", iv.Network, 0)
	return out
}
