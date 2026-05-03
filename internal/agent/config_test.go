package agent

import (
	"strings"
	"testing"
)

func TestLoad_RequiresToken(t *testing.T) {
	_, err := Load(strings.NewReader(`agent:
  log_level: debug
`))
	if err == nil {
		t.Fatal("expected error when token missing, got nil")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error should mention token, got %v", err)
	}
}

func TestLoad_AppliesDefaults(t *testing.T) {
	cfg, err := Load(strings.NewReader(`token: lh_abc`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Token != "lh_abc" {
		t.Errorf("Token = %q", cfg.Token)
	}
	if cfg.Agent.DataDir != DefaultDataDir {
		t.Errorf("DataDir default not applied: %q", cfg.Agent.DataDir)
	}
	if cfg.Agent.MaxConcurrentChecks != DefaultMaxConcurrentChecks {
		t.Errorf("MaxConcurrentChecks default not applied: %d", cfg.Agent.MaxConcurrentChecks)
	}
	if cfg.Agent.LogLevel != DefaultLogLevel {
		t.Errorf("LogLevel default not applied: %q", cfg.Agent.LogLevel)
	}
}

func TestLoad_PreservesExplicitValues(t *testing.T) {
	cfg, err := Load(strings.NewReader(`
token: lh_abc
agent:
  data_dir: /tmp/lighthouse
  max_concurrent_checks: 25
  log_level: debug
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.DataDir != "/tmp/lighthouse" {
		t.Errorf("DataDir = %q", cfg.Agent.DataDir)
	}
	if cfg.Agent.MaxConcurrentChecks != 25 {
		t.Errorf("MaxConcurrentChecks = %d", cfg.Agent.MaxConcurrentChecks)
	}
	if cfg.Agent.LogLevel != "debug" {
		t.Errorf("LogLevel = %q", cfg.Agent.LogLevel)
	}
}

func TestLoad_RejectsMalformedYAML(t *testing.T) {
	_, err := Load(strings.NewReader("not: : valid: yaml:::"))
	if err == nil {
		t.Fatal("expected parse error")
	}
}
