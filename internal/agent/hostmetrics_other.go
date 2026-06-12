//go:build !linux && !darwin && !windows

// Fallback noop collector for platforms without a per-OS implementation
// (freebsd, openbsd, illumos, …). Linux uses hostmetrics_linux.go (real
// /proc collector), darwin uses hostmetrics_darwin.go (sysctl), windows
// uses hostmetrics_windows.go (self-monitoring only for now).
//
// The runner treats an empty Collect() result as "nothing to emit this
// tick" — never errors out.
package agent

import "github.com/statusharbor/lighthouse/internal/transport"

// NewLinuxCollector is the cross-platform entrypoint name from
// hostmetrics_linux.go. The name is historical; on platforms without a real
// collector it returns the noop so the runner doesn't have to
// conditional-compile.
func NewLinuxCollector() Collector {
	return platformNoopCollector{}
}

// NewLinuxCollectorWithRoot matches the Linux constructor that accepts
// a procfs prefix. On platforms without a real collector the argument
// is ignored.
func NewLinuxCollectorWithRoot(_ string) Collector {
	return NewLinuxCollector()
}

// NewLinuxCollectorWithRoots matches the Linux constructor that takes
// both procRoot and hostRoot. On platforms without a real collector
// both arguments are ignored.
func NewLinuxCollectorWithRoots(_, _ string) Collector {
	return NewLinuxCollector()
}

type platformNoopCollector struct{}

func (platformNoopCollector) Collect() ([]transport.HostSample, error) {
	return nil, nil
}
