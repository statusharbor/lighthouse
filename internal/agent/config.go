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
	Token string      `yaml:"token"`
	Agent AgentConfig `yaml:"agent"`
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
}

// Default values applied to omitted fields.
const (
	DefaultDataDir             = "/var/lib/lighthouse"
	DefaultMaxConcurrentChecks = 10
	DefaultLogLevel            = "info"
)

// Environment-variable overrides read by Load. Each takes precedence
// over the equivalent YAML field, so container/k8s deployments can set
// these without mounting a config file.
const (
	EnvToken    = "LIGHTHOUSE_TOKEN"
	EnvDataDir  = "LIGHTHOUSE_DATA_DIR"
	EnvLogLevel = "LIGHTHOUSE_LOG_LEVEL"
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
	if cfg.Token == "" {
		return nil, fmt.Errorf("config: token is required (set in YAML or %s env)", EnvToken)
	}
	if cfg.Agent.DataDir == "" {
		cfg.Agent.DataDir = DefaultDataDir
	}
	if cfg.Agent.MaxConcurrentChecks == 0 {
		cfg.Agent.MaxConcurrentChecks = DefaultMaxConcurrentChecks
	}
	if cfg.Agent.LogLevel == "" {
		cfg.Agent.LogLevel = DefaultLogLevel
	}
	return &cfg, nil
}
