// Package ebpf is Lighthouse's shared eBPF runtime (docs/eBPF/01-foundation.md):
// host probing, per-collector requirement checks, and a Manager that runs
// each collector in isolation with restarts, a local kill switch and
// remote per-collector flags. Collectors themselves live in subpackages
// and only build on Linux; everything in this file is platform-neutral so
// the planning logic is tested everywhere.
package ebpf

import (
	"context"
	"slices"
	"time"
)

// SchemaVersion is the transport.EBPFEnvelope schema this agent writes.
const SchemaVersion = 1

// State is what the status report says about one collector.
type State string

const (
	StateRunning     State = "running"
	StateDisabled    State = "disabled"
	StateUnsupported State = "unsupported"
	StateDegraded    State = "degraded"
	StateFailed      State = "failed"
)

// Reason explains a state other than running.
type Reason string

const (
	ReasonNoBTF             Reason = "no_btf"
	ReasonMissingCapability Reason = "missing_capability"
	ReasonLockdown          Reason = "lockdown"
	ReasonMissingFeature    Reason = "missing_feature"
	ReasonLoadFailed        Reason = "load_failed"
	ReasonRestarting        Reason = "restarting"
	ReasonPartial           Reason = "partial" // running without some kernel features
	ReasonKillSwitch        Reason = "kill_switch"
	ReasonRemoteOff         Reason = "remote_off"
	ReasonNotLinux          Reason = "not_linux"
)

// Status is one collector's line in the report sent to the Console.
type Status struct {
	Collector string `json:"collector"`
	State     State  `json:"state"`
	Reason    Reason `json:"reason,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Host is the probed host, see ProbeHost.
type Host struct {
	KernelRelease string
	BTF           bool
	Capabilities  []string
	// Lockdown is the active mode from /sys/kernel/security/lockdown:
	// "none", "integrity", "confidentiality", or "" when the file is
	// missing (lockdown not built in).
	Lockdown      string
	CgroupVersion string
}

// Feature is one kernel feature a collector needs (program type, map
// type, helper). Probe returns nil when the kernel has it.
type Feature struct {
	Name  string
	Probe func() error
}

// Requirements is what a collector declares about the host it needs.
type Requirements struct {
	BTF bool
	// KernelMemory marks collectors that read kernel memory
	// (bpf_probe_read_kernel), which lockdown=confidentiality refuses.
	KernelMemory bool
	Features     []Feature
}

// Sink receives one collector's output. Gauge carries interval series
// (sent on the host-metrics remote-write path); Event carries rare events
// (wrapped in an EBPFEnvelope and sent to the events endpoint), at is the
// event time, from WallTime for kernel timestamps. Implementations never
// block.
type Sink interface {
	Gauge(name string, value float64, labels map[string]string)
	Event(kind string, at time.Time, payload any)
}

// Collector is one feature area. Run loads and attaches its programs,
// reports to sink until ctx is cancelled, and releases everything before
// returning. Returning an error (or panicking) counts as a failure and the
// Manager restarts it with backoff; returning nil after ctx is cancelled
// is a clean stop.
//
// ponytail: plan 01 sketches Start/Stop; a blocking Run with ctx
// cancellation as Stop is the same contract with less state.
type Collector interface {
	Name() string
	Requirements() Requirements
	Run(ctx context.Context, sink Sink) error
}

// Check returns the reason a collector with req cannot run on h, or "" if
// it can as far as the host is concerned. Feature probes are separate
// (they need the kernel) and run in the Manager.
//
// Loading programs needs CAP_BPF plus CAP_PERFMON (kernel 5.8+) or
// CAP_SYS_ADMIN, which older kernels require instead.
func Check(req Requirements, h Host) (Reason, string) {
	if req.BTF && !h.BTF {
		return ReasonNoBTF, "/sys/kernel/btf/vmlinux not found"
	}
	has := func(c string) bool { return slices.Contains(h.Capabilities, c) }
	if !has("CAP_SYS_ADMIN") && (!has("CAP_BPF") || !has("CAP_PERFMON")) {
		return ReasonMissingCapability, "needs CAP_BPF and CAP_PERFMON, or CAP_SYS_ADMIN"
	}
	if req.KernelMemory && h.Lockdown == "confidentiality" {
		return ReasonLockdown, "kernel lockdown is in confidentiality mode"
	}
	return "", ""
}
