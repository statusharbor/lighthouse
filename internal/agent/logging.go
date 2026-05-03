package agent

import (
	"context"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

// LoggingExecutor wraps a CheckExecutor with structured before/after slog
// events. Sensitive data (URL query strings, secret-bearing headers, body
// content, raw bytes) is stripped per the redaction policy in design §11.
//
// Logs at slog.LevelDebug — silent at default info level. The runtime log
// level comes from agent.log_level in the YAML.
type LoggingExecutor struct {
	Inner CheckExecutor
	Log   *slog.Logger
}

// NewLoggingExecutor wraps an executor for structured logging. If log is nil,
// the package-level slog.Default is used.
func NewLoggingExecutor(inner CheckExecutor, log *slog.Logger) *LoggingExecutor {
	if log == nil {
		log = slog.Default()
	}
	return &LoggingExecutor{Inner: inner, Log: log}
}

func (l *LoggingExecutor) Run(ctx context.Context, def CheckDefinition) CheckObservation {
	start := time.Now()
	l.Log.LogAttrs(ctx, slog.LevelDebug, "check.start",
		slog.String("check_id", def.ID),
		slog.String("type", def.Type),
		slog.String("target", redactTarget(def)),
		slog.Int("timeout_ms", def.TimeoutSeconds*1000),
	)

	obs := l.Inner.Run(ctx, def)

	l.Log.LogAttrs(ctx, slog.LevelDebug, "check.done",
		slog.String("check_id", def.ID),
		slog.Duration("elapsed", time.Since(start)),
		slog.String("state", string(obs.State)),
		slog.Int("status_code", obs.StatusCode),
		slog.Int("response_time_ms", obs.ResponseTimeMs),
		slog.String("error", redactError(obs.ErrorMessage)),
	)
	return obs
}

// redactTarget drops the query string from URLs (which routinely carry
// `?api_key=…`, `?token=…`, etc.) and otherwise leaves the host+path
// intact. Non-URL targets (TCP/UDP host:port) pass through unchanged.
func redactTarget(def CheckDefinition) string {
	t := strings.ToLower(def.Type)
	if t != "http" && t != "https" {
		return def.URL
	}
	u, err := url.Parse(def.URL)
	if err != nil || u.Scheme == "" {
		return def.URL
	}
	if u.RawQuery == "" {
		return u.String()
	}
	u.RawQuery = ""
	return u.String() + "?...redacted..."
}

// redactError strips query strings from any URL fragments embedded in the
// error message — these come from net/http error formatting which may
// include the full URL we just hit.
func redactError(msg string) string {
	if msg == "" {
		return ""
	}
	// Cheap and sufficient: replace anything between `?` and the next
	// space/quote with the redaction sentinel. Errors are short and
	// human-readable; this loses nothing important.
	return redactQueryStrings(msg)
}

func redactQueryStrings(s string) string {
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '?' {
			out.WriteByte(s[i])
			continue
		}
		out.WriteString("?...redacted...")
		// Skip until we hit whitespace, quote, or end.
		for i+1 < len(s) {
			c := s[i+1]
			if c == ' ' || c == '\t' || c == '\n' || c == '"' || c == '\'' {
				break
			}
			i++
		}
	}
	return out.String()
}

// SafeHeaderValue is a small predicate the executors can use when they
// decide which response headers to surface in error messages. Returns
// false for any header name matching the design §11.1 denylist.
//
// Exposed so internal/checks can reuse the policy if/when we extend
// HTTP error reporting to include headers.
func SafeHeaderValue(name string) bool {
	lower := strings.ToLower(name)
	for _, exact := range []string{"authorization", "cookie", "set-cookie", "proxy-authorization"} {
		if lower == exact {
			return false
		}
	}
	for _, pattern := range []string{"token", "secret", "key", "auth", "password"} {
		if strings.Contains(lower, pattern) {
			return false
		}
	}
	return true
}
