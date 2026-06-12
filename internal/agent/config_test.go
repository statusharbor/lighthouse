package agent

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_RequiresToken(t *testing.T) {
	t.Setenv(EnvToken, "")
	t.Setenv(EnvDataDir, "")
	t.Setenv(EnvLogLevel, "")
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

func TestLoad_EnvTokenSuppliesMissingToken(t *testing.T) {
	t.Setenv(EnvToken, "lh_from_env")
	cfg, err := Load(strings.NewReader(`agent:
  log_level: debug
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Token != "lh_from_env" {
		t.Errorf("Token should come from env, got %q", cfg.Token)
	}
}

func TestLoad_EnvTokenOverridesYAML(t *testing.T) {
	t.Setenv(EnvToken, "lh_env_wins")
	cfg, err := Load(strings.NewReader(`token: lh_yaml`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Token != "lh_env_wins" {
		t.Errorf("env should override YAML, got %q", cfg.Token)
	}
}

func TestLoad_EnvDataDirOverridesYAML(t *testing.T) {
	t.Setenv(EnvToken, "")
	t.Setenv(EnvDataDir, "/srv/lh-data")
	cfg, err := Load(strings.NewReader(`
token: lh_x
agent:
  data_dir: /var/lib/lighthouse
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.DataDir != "/srv/lh-data" {
		t.Errorf("env should override YAML, got %q", cfg.Agent.DataDir)
	}
}

func TestLoad_EnvDataDirSuppliesMissingValue(t *testing.T) {
	t.Setenv(EnvToken, "")
	t.Setenv(EnvDataDir, "/srv/lh-data")
	cfg, err := Load(strings.NewReader(`token: lh_x`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.DataDir != "/srv/lh-data" {
		t.Errorf("env should supply data_dir when YAML omits it, got %q", cfg.Agent.DataDir)
	}
}

func TestLoad_EnvLogLevelOverridesYAML(t *testing.T) {
	t.Setenv(EnvToken, "")
	t.Setenv(EnvLogLevel, "debug")
	cfg, err := Load(strings.NewReader(`
token: lh_x
agent:
  log_level: info
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.LogLevel != "debug" {
		t.Errorf("env should override YAML, got %q", cfg.Agent.LogLevel)
	}
}

func TestLoadFile_MissingFileFallsBackToEnv(t *testing.T) {
	t.Setenv(EnvToken, "lh_env_only")
	cfg, err := LoadFile(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("LoadFile should tolerate missing file when env supplies token: %v", err)
	}
	if cfg.Token != "lh_env_only" {
		t.Errorf("Token = %q", cfg.Token)
	}
	if cfg.Agent.DataDir != DefaultDataDirForOS() {
		t.Errorf("defaults should still apply, got DataDir=%q want=%q", cfg.Agent.DataDir, DefaultDataDirForOS())
	}
}

func TestLoadFile_MissingFileAndNoEnvErrors(t *testing.T) {
	t.Setenv(EnvToken, "")
	t.Setenv(EnvDataDir, "")
	t.Setenv(EnvLogLevel, "")
	_, err := LoadFile(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected error when neither file nor env provides token")
	}
}

func TestLoad_AppliesDefaults(t *testing.T) {
	t.Setenv(EnvToken, "")
	t.Setenv(EnvDataDir, "")
	t.Setenv(EnvLogLevel, "")
	cfg, err := Load(strings.NewReader(`token: lh_abc`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Token != "lh_abc" {
		t.Errorf("Token = %q", cfg.Token)
	}
	if cfg.Agent.DataDir != DefaultDataDirForOS() {
		t.Errorf("DataDir default not applied: %q want=%q", cfg.Agent.DataDir, DefaultDataDirForOS())
	}
	if cfg.Agent.MaxConcurrentChecks != DefaultMaxConcurrentChecks {
		t.Errorf("MaxConcurrentChecks default not applied: %d", cfg.Agent.MaxConcurrentChecks)
	}
	if cfg.Agent.LogLevel != DefaultLogLevel {
		t.Errorf("LogLevel default not applied: %q", cfg.Agent.LogLevel)
	}
}

func TestLoad_PreservesExplicitValues(t *testing.T) {
	t.Setenv(EnvToken, "")
	t.Setenv(EnvDataDir, "")
	t.Setenv(EnvLogLevel, "")
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

// Role validation: an unknown value (typo, leftover from an old
// spec) must hard-fail rather than silently default to "central".
// A DaemonSet pod running checks would multiply every check across
// every node — production impact is worse than the crash loop.
func TestLoad_RejectsUnknownRole(t *testing.T) {
	yamlIn := "token: lh_x\nagent:\n  role: hostmetrics\n" // missing underscore
	_, err := Load(strings.NewReader(yamlIn))
	if err == nil {
		t.Fatal("expected error on unknown role; got nil")
	}
}

// Empty role and the two recognised values must all parse — empty
// canonicalises to "central" inside IsHostMetricsOnly.
func TestLoad_AcceptsKnownRoles(t *testing.T) {
	cases := []string{"", RoleCentral, RoleHostMetrics}
	for _, role := range cases {
		t.Run(role, func(t *testing.T) {
			yamlIn := "token: lh_x\nagent:\n  role: \"" + role + "\"\n"
			cfg, err := Load(strings.NewReader(yamlIn))
			if err != nil {
				t.Fatalf("role=%q: %v", role, err)
			}
			if cfg.Agent.Role != role {
				t.Errorf("Role = %q, want %q", cfg.Agent.Role, role)
			}
		})
	}
}
