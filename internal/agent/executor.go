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
	// CertDaysToExpiry is set only by the SSL check, whenever a leaf
	// certificate was read (valid OR expired). nil for every other check
	// type. The heartbeat rolls these up into the cert_expiry map.
	CertDaysToExpiry *int
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
	// DNS-only fields. DNSRecordType defaults to "A" when empty;
	// DNSExpectedIPs are the expected resolved value(s); DNSResolver is an
	// optional explicit resolver `host` or `host:port` (default port 53).
	DNSRecordType  string
	DNSExpectedIPs []string
	DNSResolver    string
}

// Equal returns true when every field matches by value (deep on the
// header + DNS slices). Used by the scheduler supervisor to decide
// whether a check's goroutine needs restarting on each
// supervisorTickInterval pass.
//
// We hand-roll this instead of reflect.DeepEqual to avoid the
// reflection cost: with N checks and M ticks/hour the supervisor
// does N×M deep-equal walks, and reflection ~10-100x slower than
// direct field comparison adds up at fleet scale. Also makes future
// "hash CheckDefinition for the config etag" a trivial extension.
//
// Slice equality is order-sensitive — RequestHeaders[0]/[1] swapped
// counts as a change. That's intentional: header order matters for
// some APIs, and a definition-side reordering is a real "this is
// different" event the supervisor should react to.
func (d CheckDefinition) Equal(other CheckDefinition) bool {
	if d.ID != other.ID ||
		d.Type != other.Type ||
		d.Name != other.Name ||
		d.URL != other.URL ||
		d.Method != other.Method ||
		d.ExpectedStatusCode != other.ExpectedStatusCode ||
		d.IntervalSeconds != other.IntervalSeconds ||
		d.TimeoutSeconds != other.TimeoutSeconds ||
		d.KeywordCheck != other.KeywordCheck ||
		d.KeywordPresent != other.KeywordPresent ||
		d.RequestBody != other.RequestBody ||
		d.SkipTLSVerify != other.SkipTLSVerify ||
		d.DNSRecordType != other.DNSRecordType ||
		d.DNSResolver != other.DNSResolver {
		return false
	}
	if len(d.RequestHeaders) != len(other.RequestHeaders) {
		return false
	}
	for i, h := range d.RequestHeaders {
		if h != other.RequestHeaders[i] {
			return false
		}
	}
	if len(d.ExpectedHeaders) != len(other.ExpectedHeaders) {
		return false
	}
	for i, h := range d.ExpectedHeaders {
		if h != other.ExpectedHeaders[i] {
			return false
		}
	}
	if len(d.DNSExpectedIPs) != len(other.DNSExpectedIPs) {
		return false
	}
	for i, s := range d.DNSExpectedIPs {
		if s != other.DNSExpectedIPs[i] {
			return false
		}
	}
	return true
}
