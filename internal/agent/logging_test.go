package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// captureLogger returns a slog.Logger wired to a buffer plus a function
// that yields each log record as a parsed map.
func captureLogger(t *testing.T) (*slog.Logger, func() []map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(h)
	parse := func() []map[string]any {
		var out []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Fatalf("parse log line %q: %v", line, err)
			}
			out = append(out, m)
		}
		return out
	}
	return logger, parse
}

type fixedExec struct{ obs CheckObservation }

func (f fixedExec) Run(_ context.Context, _ CheckDefinition) CheckObservation { return f.obs }

func TestLoggingExecutor_StripsQueryString(t *testing.T) {
	logger, records := captureLogger(t)
	wrapped := NewLoggingExecutor(fixedExec{
		obs: CheckObservation{State: StateUp, ResponseTimeMs: 12, StatusCode: 200, ObservedAt: time.Now()},
	}, logger)

	wrapped.Run(context.Background(), CheckDefinition{
		ID: "c1", Type: "https",
		URL:             "https://internal.corp.local/healthz?api_key=very-secret&token=xyz",
		TimeoutSeconds:  10,
	})

	for _, r := range records() {
		target, _ := r["target"].(string)
		if strings.Contains(target, "very-secret") || strings.Contains(target, "api_key") || strings.Contains(target, "xyz") {
			t.Errorf("query string leaked into log: target=%q", target)
		}
	}
}

func TestLoggingExecutor_LogsBeforeAndAfter(t *testing.T) {
	logger, records := captureLogger(t)
	wrapped := NewLoggingExecutor(fixedExec{
		obs: CheckObservation{State: StateDown, ErrorMessage: "i/o timeout"},
	}, logger)

	wrapped.Run(context.Background(), CheckDefinition{
		ID: "c2", Type: "tcp", URL: "10.0.4.21:5432", TimeoutSeconds: 5,
	})

	rs := records()
	if len(rs) != 2 {
		t.Fatalf("expected 2 log lines (start + done), got %d", len(rs))
	}
	if rs[0]["msg"] != "check.start" || rs[1]["msg"] != "check.done" {
		t.Errorf("unexpected msgs: %q, %q", rs[0]["msg"], rs[1]["msg"])
	}
	if rs[1]["state"] != "down" {
		t.Errorf("done log must carry state, got %v", rs[1]["state"])
	}
}

func TestLoggingExecutor_PassesThroughObservation(t *testing.T) {
	logger, _ := captureLogger(t)
	want := CheckObservation{State: StateUp, ResponseTimeMs: 99, StatusCode: 204}
	wrapped := NewLoggingExecutor(fixedExec{obs: want}, logger)
	got := wrapped.Run(context.Background(), CheckDefinition{ID: "c3", Type: "http", URL: "http://x"})
	if got.State != want.State || got.ResponseTimeMs != want.ResponseTimeMs || got.StatusCode != want.StatusCode {
		t.Errorf("LoggingExecutor must not mutate the observation: got %+v", got)
	}
}

func TestRedactQueryStrings_ErrorMessage(t *testing.T) {
	// HTTP errors often include the full URL; query string must be stripped.
	got := redactQueryStrings(`request failed: Get "https://x/y?secret=z": dial tcp: i/o timeout`)
	if strings.Contains(got, "secret=z") {
		t.Errorf("redaction failed: %s", got)
	}
	if !strings.Contains(got, "?...redacted...") {
		t.Errorf("expected redaction sentinel: %s", got)
	}
}

func TestSafeHeaderValue(t *testing.T) {
	cases := map[string]bool{
		"Content-Type":         true,
		"Server":               true,
		"Date":                 true,
		"Authorization":        false,
		"Cookie":               false,
		"Set-Cookie":           false,
		"Proxy-Authorization":  false,
		"X-Api-Key":            false,
		"X-Auth-Token":         false,
		"X-CSRF-Token":         false,
		"my-secret-header":     false,
		"x-password-hint":      false,
		"x-some-key-id":        false,
	}
	for name, want := range cases {
		if got := SafeHeaderValue(name); got != want {
			t.Errorf("SafeHeaderValue(%q) = %v, want %v", name, got, want)
		}
	}
}
