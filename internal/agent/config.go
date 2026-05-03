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

	"gopkg.in/yaml.v3"
)

// ConsoleURL is the hardcoded Status Harbor ingress for agent traffic. Not
// configurable — see design doc §7.2 (single secret, no drift between token
// and URL).
const ConsoleURL = "https://lighthouse.statusharbor.io"

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
}

// Default values applied to omitted fields.
const (
	DefaultDataDir             = "/var/lib/lighthouse"
	DefaultMaxConcurrentChecks = 10
	DefaultLogLevel            = "info"
)

// LoadFile reads a Config from the given YAML path.
func LoadFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer func() { _ = f.Close() }()
	return Load(f)
}

// Load parses YAML config from any reader. Empty fields fall back to the
// Default* constants. Returns an error when the token is missing — without
// it the agent cannot authenticate to the Console.
func Load(r io.Reader) (*Config, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Token == "" {
		return nil, errors.New("config: token is required")
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
