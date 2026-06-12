// Package agent contains the Lighthouse runtime: config load, transport
// orchestration, check scheduling, and lifecycle hooks.
//
// All Console-facing details (hardcoded URL, /api/lighthouse/v1/* paths,
// scoped-token auth) live in the transport package; this package owns
// behavior, not protocol details.
package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// ConsoleURL is the Status Harbor ingress for agent traffic. Hardcoded for
// production builds so customers can't accidentally redirect agents at a
// stranger's Console (see design §7.2 — single secret, no URL drift).
//
// Overridable at build time via:
//   go build -ldflags="-X github.com/statusharbor/lighthouse/internal/agent.ConsoleURL=https://test/"
//
// Used by the cross-repo smoke test in the main repo's e2e harness.
var ConsoleURL = "https://lighthouse.statusharbor.io"

// Config is the on-disk configuration written by install.sh. Only `token`
// is required.
type Config struct {
	Token     string          `yaml:"token"`
	Agent     AgentConfig     `yaml:"agent"`
	Discovery DiscoveryConfig `yaml:"discovery"`
}

// DiscoveryConfig governs the Kubernetes Ingress watcher. Discovery is
// off unless Enabled is true. When enabled outside a cluster the
// watcher silently no-ops — the agent doesn't error.
//
// Namespaces semantics:
//   - empty list or ["*"] ⇒ all-namespaces (needs ClusterRole)
//   - ["a", "b"]          ⇒ scoped to those namespaces (per-namespace Role)
type DiscoveryConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Namespaces []string `yaml:"namespaces"`
}

// AgentConfig contains operational tuning. Defaults are applied by Load when
// fields are zero-valued.
type AgentConfig struct {
	DataDir             string `yaml:"data_dir"`
	MaxConcurrentChecks int    `yaml:"max_concurrent_checks"`
	LogLevel            string `yaml:"log_level"`
	// HealthPort exposes /healthz/{live,ready} on this TCP port for
	// Kubernetes probes. Zero (the default) disables the listener;
	// the Helm chart sets it to 9093.
	HealthPort int `yaml:"health_port"`
	// ProcRoot is the prefix the Linux host-metric collector prepends
	// to "/stat", "/meminfo", "/net/dev", etc. Defaults to "/proc"
	// (bare-metal / VM). The DaemonSet flavour of the Helm chart sets
	// this to "/host/proc" so the agent reads the **node's** /proc
	// through a hostPath mount instead of the container's view (which
	// only sees its own pid namespace). Honoured by Linux only —
	// macOS / Windows collectors use platform APIs, not /proc.
	ProcRoot string `yaml:"proc_root"`
	// HostRoot is the prefix the Linux host-metric collector prepends
	// before calling syscall.Statfs on each mountpoint from /proc/mounts.
	// Empty (the default) means "no prefix" — Statfs runs on the bare
	// mountpoint, which is correct for bare-metal / VM installs.
	//
	// For the DaemonSet flavour, /proc/mounts (read via ProcRoot) lists
	// the **host's** mountpoints, but Statfs resolves those paths through
	// the **pod's** own mount namespace — so /var/lib/docker on the host
	// either doesn't exist in the pod (silently skipped) or, worse,
	// resolves to a same-named path inside the container. Mounting the
	// host's / read-only at /host/root and setting HostRoot=/host/root
	// makes Statfs land on the real host filesystem, so disk_used_bytes
	// / disk_free_bytes / disk_used_percent reflect the node.
	//
	// The metric label "mount" stays the unprefixed host path — only the
	// syscall is rerouted.
	HostRoot string `yaml:"host_root"`
	// Role picks which work this agent does. Two values:
	//
	//   - ""          / "central" — default. Run checks, discovery,
	//                                heartbeats, host-metrics.
	//   - "host_metrics"          — host-metric reporter only. Skip the
	//                                check scheduler and the Ingress
	//                                discovery watcher. Still registers
	//                                and heartbeats so the Console can
	//                                track per-node liveness.
	//
	// The DaemonSet workload in the Helm chart sets this to
	// "host_metrics" while the central Deployment uses the default. A
	// cluster running both ends up with one pod scheduling checks +
	// discovery and N pods reporting per-node /proc — vs. a
	// pre-Phase-2 install where N pods all duplicate every check
	// (accepted by multi-instance but a needless amount of work). See
	// docs/victoriametrics/lighthause/PLAN.md §2.1 (status-harbor).
	Role string `yaml:"role"`
}

// Roles understood by Role above. RoleCentral is the implicit default —
// missing config means "run everything", mirroring the pre-DaemonSet
// behaviour.
const (
	RoleCentral      = "central"
	RoleHostMetrics  = "host_metrics"
)

// IsHostMetricsOnly reports whether the agent should skip checks +
// discovery. Centralises the role check so the gating in main.go
// doesn't drift from the cfg field's spelling.
func (a AgentConfig) IsHostMetricsOnly() bool {
	return a.Role == RoleHostMetrics
}

// Default values applied to omitted fields. DefaultDataDir is the
// Unix-shaped fallback; the actual default at runtime is picked by
// DefaultDataDirForOS so Windows/macOS get a path their service
// account can actually write to. Keeping the constant lets older
// tests / explicit Unix consumers keep working unchanged.
const (
	DefaultDataDir             = "/var/lib/lighthouse"
	DefaultMaxConcurrentChecks = 10
	DefaultLogLevel            = "info"
	// DefaultProcRoot is the path the Linux collector reads when
	// the operator hasn't overridden via YAML / env. Matches the
	// kernel's mount of procfs on every Linux distro.
	DefaultProcRoot = "/proc"
)

// DefaultDataDirForOS returns the canonical per-OS data directory for
// the agent:
//
//   - linux:   /var/lib/lighthouse — systemd unit's default WorkingDirectory.
//   - darwin:  /Library/Application Support/Lighthouse — the Apple-blessed
//              system-wide location for daemons.
//   - windows: %ProgramData%\Lighthouse — readable by every service
//              account (LocalSystem included). Falls back to
//              os.UserConfigDir() (%APPDATA%) for user-mode installs
//              when ProgramData isn't set (extremely unusual).
//
// All operators can still override via the LIGHTHOUSE_DATA_DIR env var
// or the `agent.data_dir` YAML key. We never panic — a last-resort
// hardcoded path keeps the constructor total even when env lookups fail.
func DefaultDataDirForOS() string {
	switch runtime.GOOS {
	case "windows":
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "Lighthouse")
		}
		if d, err := os.UserConfigDir(); err == nil {
			return filepath.Join(d, "Lighthouse")
		}
		return `C:\Lighthouse`
	case "darwin":
		return "/Library/Application Support/Lighthouse"
	default:
		return DefaultDataDir
	}
}

// Environment-variable overrides read by Load. Each takes precedence
// over the equivalent YAML field, so container/k8s deployments can set
// these without mounting a config file.
const (
	EnvToken               = "LIGHTHOUSE_TOKEN"
	EnvDataDir             = "LIGHTHOUSE_DATA_DIR"
	EnvLogLevel            = "LIGHTHOUSE_LOG_LEVEL"
	EnvDiscoveryEnabled    = "LIGHTHOUSE_DISCOVERY_ENABLED"
	EnvDiscoveryNamespaces = "LIGHTHOUSE_DISCOVERY_NAMESPACES" // comma-separated; "*" allowed
	EnvProcRoot            = "LIGHTHOUSE_PROC_ROOT"            // DaemonSet pods set this to /host/proc
	EnvHostRoot            = "LIGHTHOUSE_HOST_ROOT"            // DaemonSet pods set this to /host/root when mountHostRoot is on
	EnvRole                = "LIGHTHOUSE_ROLE"                 // "" / "central" / "host_metrics"
)

// LoadFile reads a Config from the given YAML path. A missing file is not
// an error: Load is invoked with empty input so the LIGHTHOUSE_TOKEN env
// var (if set) can supply the token without any on-disk config.
func LoadFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Load(strings.NewReader(""))
		}
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer func() { _ = f.Close() }()
	return Load(f)
}

// Load parses YAML config from any reader and applies environment-variable
// overrides. The LIGHTHOUSE_TOKEN env var (if set and non-empty) takes
// precedence over the `token:` field in YAML. Empty fields fall back to
// the Default* constants. Returns an error when the token is missing
// from both YAML and env — without it the agent cannot authenticate.
func Load(r io.Reader) (*Config, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if len(b) > 0 {
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	if v := os.Getenv(EnvToken); v != "" {
		cfg.Token = v
	}
	if v := os.Getenv(EnvDataDir); v != "" {
		cfg.Agent.DataDir = v
	}
	if v := os.Getenv(EnvLogLevel); v != "" {
		cfg.Agent.LogLevel = v
	}
	if v := os.Getenv(EnvProcRoot); v != "" {
		cfg.Agent.ProcRoot = v
	}
	if v := os.Getenv(EnvHostRoot); v != "" {
		cfg.Agent.HostRoot = v
	}
	if v := os.Getenv(EnvRole); v != "" {
		cfg.Agent.Role = v
	}
	if v := os.Getenv(EnvDiscoveryEnabled); v != "" {
		cfg.Discovery.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv(EnvDiscoveryNamespaces); v != "" {
		cfg.Discovery.Namespaces = nil
		for _, ns := range strings.Split(v, ",") {
			if ns = strings.TrimSpace(ns); ns != "" {
				cfg.Discovery.Namespaces = append(cfg.Discovery.Namespaces, ns)
			}
		}
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("config: token is required (set in YAML or %s env)", EnvToken)
	}
	if cfg.Agent.DataDir == "" {
		cfg.Agent.DataDir = DefaultDataDirForOS()
	}
	if cfg.Agent.MaxConcurrentChecks == 0 {
		cfg.Agent.MaxConcurrentChecks = DefaultMaxConcurrentChecks
	}
	if cfg.Agent.LogLevel == "" {
		cfg.Agent.LogLevel = DefaultLogLevel
	}
	if cfg.Agent.ProcRoot == "" {
		cfg.Agent.ProcRoot = DefaultProcRoot
	}
	// Validate Role against the closed enum — silent fallback to
	// "central" on a typo (e.g. LIGHTHOUSE_ROLE=hostmetrics, missing
	// the underscore) would put a DaemonSet pod into the central
	// role and start it scheduling every check N times across the
	// cluster. Hard fail at boot so the typo surfaces in the pod's
	// CrashLoopBackOff rather than as confusing duplicate-check
	// traffic in production.
	switch cfg.Agent.Role {
	case "", RoleCentral, RoleHostMetrics:
		// ok — "" canonicalises to central via IsHostMetricsOnly
	default:
		return nil, fmt.Errorf(
			"config: unknown agent.role %q (set via %s env or agent.role YAML; must be %q or %q)",
			cfg.Agent.Role, EnvRole, RoleCentral, RoleHostMetrics,
		)
	}
	return &cfg, nil
}
