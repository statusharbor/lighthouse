//go:build linux

package usage

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/statusharbor/lighthouse/internal/ebpf/identity"
	"github.com/statusharbor/lighthouse/internal/transport"
)

const (
	userHZ   = 100 // USER_HZ, the unit of /proc/<pid>/stat CPU times
	pageSize = 4096
)

// Poller is the host-metrics collector for per-process attribution: it
// polls /proc for CPU and memory and cgroup io.stat for device I/O, and
// reports the Accountant's interval (with what eBPF collectors fed it) as
// top-N gauges. It needs no eBPF.
type Poller struct {
	Acct       *Accountant
	ProcRoot   string
	CgroupRoot string
	Pods       func(ctx context.Context, podUID string) (namespace, name string, ok bool)

	mu       sync.Mutex
	groups   map[identity.Key]string
	busy     uint64
	total    uint64
	lastIO   map[string]uint64
	lastIOAt time.Time
	numCPU   float64
}

func NewPoller(acct *Accountant, procRoot string, pods func(context.Context, string) (string, string, bool)) *Poller {
	cg := filepath.Join(procRoot, "1", "root", "sys", "fs", "cgroup")
	if _, err := os.Stat(filepath.Join(cg, "cgroup.controllers")); err != nil {
		cg = "/sys/fs/cgroup"
	}
	return &Poller{Acct: acct, ProcRoot: procRoot, CgroupRoot: cg, Pods: pods, groups: map[identity.Key]string{}, lastIO: map[string]uint64{}}
}

// group resolves (and caches) a process's group from its cgroup file.
func (p *Poller) group(ctx context.Context, k identity.Key, comm string, kthread bool) string {
	if g, ok := p.groups[k]; ok {
		return g
	}
	var proc identity.Process
	if cg, err := os.ReadFile(filepath.Join(p.ProcRoot, strconv.FormatUint(uint64(k.PID), 10), "cgroup")); err == nil {
		var podUID string
		proc.ContainerID, podUID, proc.Unit = identity.FromCgroupFile(string(cg))
		if podUID != "" && p.Pods != nil {
			proc.Namespace, proc.Pod, _ = p.Pods(ctx, podUID)
		}
	}
	g := Group(proc, comm, kthread)
	p.groups[k] = g
	return g
}

// GroupOf is for eBPF collectors resolving a process they saw.
func (p *Poller) GroupOf(ctx context.Context, k identity.Key, comm string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.group(ctx, k, comm, false)
}

func (p *Poller) Collect() ([]transport.HostSample, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx := context.Background()
	now := time.Now()
	var procs []Proc
	seen := map[identity.Key]bool{}
	dirs, _ := os.ReadDir(p.ProcRoot)
	for _, d := range dirs {
		pid, err := strconv.ParseUint(d.Name(), 10, 32)
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(p.ProcRoot, d.Name(), "stat"))
		if err != nil {
			continue
		}
		st, ok := parseProcStat(string(raw))
		if !ok {
			continue
		}
		k := identity.Key{PID: uint32(pid), StartTicks: st.startTicks}
		seen[k] = true
		procs = append(procs, Proc{Key: k, Group: p.group(ctx, k, st.comm, st.kernelThread), CPUNS: st.cpuTicks * (1e9 / userHZ), RSS: st.rssPages * pageSize})
	}
	for k := range p.groups {
		if !seen[k] {
			delete(p.groups, k)
		}
	}

	var hostCores float64
	if f, err := os.Open(filepath.Join(p.ProcRoot, "stat")); err == nil {
		busy, total := hostBusyTicks(f)
		_ = f.Close()
		if p.total > 0 && total > p.total {
			// busy share of all CPU time, times the CPU count: cores in use.
			if p.numCPU == 0 {
				p.numCPU = float64(countCPUs(filepath.Join(p.ProcRoot, "stat")))
			}
			hostCores = float64(busy-p.busy) / float64(total-p.total) * p.numCPU
		}
		p.busy, p.total = busy, total
	}

	device := p.deviceIO(ctx, now)
	iv, ok := p.Acct.Poll(procs, now)
	if !ok {
		return nil, nil
	}
	return samples(iv, device, hostCores, now), nil
}

func countCPUs(statPath string) int {
	raw, _ := os.ReadFile(statPath)
	n := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "cpu") && !strings.HasPrefix(line, "cpu ") {
			n++
		}
	}
	return max(n, 1)
}

// deviceIO reads io.stat of container and systemd service cgroups and
// returns bytes per second per group since the last call. Buffered writes
// are flushed by kernel threads but charged to the writer's cgroup, so the
// writing container is credited, not a kernel thread (PRC-U-F10).
func (p *Poller) deviceIO(ctx context.Context, now time.Time) map[string]float64 {
	out := map[string]float64{}
	cur := map[string]uint64{}
	elapsed := now.Sub(p.lastIOAt).Seconds()
	_ = filepath.WalkDir(p.CgroupRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if strings.Count(strings.TrimPrefix(path, p.CgroupRoot), "/") > 8 {
			return filepath.SkipDir
		}
		rel := strings.TrimPrefix(path, p.CgroupRoot)
		containerID, podUID := identity.ParseCgroupPath(rel)
		var proc identity.Process
		switch {
		case containerID != "":
			proc.ContainerID = containerID
			if podUID != "" && p.Pods != nil {
				proc.Namespace, proc.Pod, _ = p.Pods(ctx, podUID)
			}
		case strings.HasSuffix(d.Name(), ".service"):
			proc.Unit = d.Name()
		default:
			return nil
		}
		f, err := os.Open(filepath.Join(path, "io.stat"))
		if err != nil {
			return nil
		}
		b := ioStatBytes(f)
		_ = f.Close()
		cur[path] = b
		if prev, ok := p.lastIO[path]; ok && b >= prev && elapsed > 0 {
			out[Group(proc, "", false)] += float64(b-prev) / elapsed
		}
		return filepath.SkipDir // sub-cgroups are inside this total
	})
	p.lastIO, p.lastIOAt = cur, now
	return out
}
