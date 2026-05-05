package agent

import (
	"context"
	"time"
)

// State is the up/down outcome of a single check observation. Constrained to
// match the server's CHECK constraint on lighthouse_check_events.new_state.
type State string

const (
	StateUp   State = "up"
	StateDown State = "down"
)

// CheckObservation is what an executor returns for a single run of a check.
// Latency, status code, and error are diagnostic fields surfaced on
// transition events (per design §3.2).
type CheckObservation struct {
	State          State
	ResponseTimeMs int    // 0 if not measured
	StatusCode     int    // HTTP status code, 0 for non-HTTP checks
	ErrorMessage   string // empty on success
	ObservedAt     time.Time
}

// CheckExecutor is the agent's abstraction over check types — the real
// implementations (http/https/tcp/udp) plug in here. Tests pass mock
// executors so the runner can be exercised hermetically.
//
// Run must be context-cancellation aware: the runner cancels in-flight
// checks during graceful shutdown.
type CheckExecutor interface {
	Run(ctx context.Context, def CheckDefinition) CheckObservation
}

// HeaderPair is one custom request header to add to outbound HTTP requests.
// Mirror of transport.HeaderPair (kept local so the executor surface
// doesn't pull in transport types).
type HeaderPair struct {
	Key   string
	Value string
}

// ExpectedHeader is one response-header validation rule. Match is one of
// "present" | "exact" | "contains"; when "present", Value is ignored.
// Mirror of transport.ExpectedHeader.
type ExpectedHeader struct {
	Key   string
	Value string
	Match string
}

// CheckDefinition is the agent-internal view of a check. It mirrors the
// transport-layer CheckDef but lives in the agent package so the executor
// surface doesn't pull in transport types. The runner translates between
// the two at boundaries.
type CheckDefinition struct {
	ID                 string
	Type               string
	Name               string
	URL                string
	Method             string
	ExpectedStatusCode int
	IntervalSeconds    int
	TimeoutSeconds     int
	KeywordCheck       string
	KeywordPresent     bool
	RequestHeaders     []HeaderPair
	RequestBody        string
	ExpectedHeaders    []ExpectedHeader
	SkipTLSVerify      bool
}
