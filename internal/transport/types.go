// Package transport handles HTTPS communication with the Status Harbor
// Console. It owns the URL, the auth header shape, the JSON contract, and
// retry policy. Everything else in the agent treats the Console as an
// abstract sink.
package transport

import "time"

// RegisterRequest is what the agent posts to /api/lighthouse/v1/register on
// startup. Per design §4.1: the lighthouse_id is NOT sent — server resolves
// it from the bound token.
type RegisterRequest struct {
	AgentVersion  string `json:"agent_version"`
	AgentHostname string `json:"agent_hostname"`
}

// RegisterResponse is what the Console returns from /register. Carries the
// per-agent operating parameters (heartbeat cadence, flap threshold) plus
// the initial check set.
type RegisterResponse struct {
	LighthouseID             string         `json:"lighthouse_id"`
	Name                     string         `json:"name"`
	Host                     string         `json:"host"`
	Paused                   bool           `json:"paused"`
	HeartbeatIntervalSeconds int            `json:"heartbeat_interval_seconds"`
	FlapProtectionThreshold  int            `json:"flap_protection_threshold"`
	ConfigEtag               string         `json:"config_etag"`
	Checks                   []CheckDef     `json:"checks"`
}

// HeaderPair is one custom request header the Console wants the agent to
// add to outbound HTTP requests. JSON shape mirrors the Console's
// `agentHeaderPair`.
type HeaderPair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ExpectedHeader is one response-header validation rule. Match is one of
// "present" | "exact" | "contains"; when "present", Value is ignored. JSON
// shape mirrors the Console's `agentExpectedHeader`.
type ExpectedHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Match string `json:"match"`
}

// CheckDef is the agent-side view of a check definition. Mirrors the JSON
// shape returned by the Console; not every field applies to every check
// type (see Type).
type CheckDef struct {
	ID                 string           `json:"id"`
	Type               string           `json:"type"`           // http | https | tcp | udp
	Name               string           `json:"name"`
	URL                string           `json:"url,omitempty"`
	Method             string           `json:"method,omitempty"`
	ExpectedStatusCode int              `json:"expected_status_code,omitempty"`
	IntervalSeconds    int              `json:"interval_seconds"`
	TimeoutSeconds     int              `json:"timeout_seconds"`
	KeywordCheck       string           `json:"keyword_check,omitempty"`
	KeywordPresent     bool             `json:"keyword_present,omitempty"`
	RequestHeaders     []HeaderPair     `json:"request_headers,omitempty"`
	RequestBody        string           `json:"request_body,omitempty"`
	ExpectedHeaders    []ExpectedHeader `json:"expected_headers,omitempty"`
	SkipTLSVerify      bool             `json:"skip_tls_verify,omitempty"`
}

// HeartbeatInterval converts the response's seconds field to a Duration.
func (r *RegisterResponse) HeartbeatInterval() time.Duration {
	return time.Duration(r.HeartbeatIntervalSeconds) * time.Second
}

// EventsRequest is what the agent posts to /api/lighthouse/v1/events. The
// initial-sync dump (every restart) sets IsInitialSync=true; subsequent
// transition batches set it false. Per design §3.2 / §4.3.
type EventsRequest struct {
	IsInitialSync bool         `json:"is_initial_sync"`
	Events        []EventInput `json:"events"`
}

// EventInput is one state transition. PrevState is nil on initial-sync rows
// (server treats prev_state=NULL specially per Interpretation B).
type EventInput struct {
	CheckID         string  `json:"check_id"`
	PrevState       *string `json:"prev_state"`
	NewState        string  `json:"new_state"` // "up" | "down"
	ResponseTimeMs  *int    `json:"response_time_ms,omitempty"`
	StatusCode      *int    `json:"status_code,omitempty"`
	ErrorMessage    *string `json:"error_message,omitempty"`
	AgentObservedAt time.Time `json:"agent_observed_at"`
}

// EventsResponse is the server's ack: the count it persisted (which differs
// from len(Events) when ON CONFLICT skips duplicates).
type EventsResponse struct {
	Received int `json:"received"`
}

// HeartbeatRequest is what the agent posts every heartbeat_interval seconds
// per design §4.2. ConfigEtag is the agent's last-known etag — when it
// matches, the server omits `checks` from the response to save bandwidth.
type HeartbeatRequest struct {
	AgentVersion   string                  `json:"agent_version"`
	ConfigEtag     string                  `json:"config_etag,omitempty"`
	CheckLatencies map[string]LatencyEntry `json:"check_latencies,omitempty"`
}

// LatencyEntry is a sparse per-check latency snapshot included in the
// heartbeat. The map only contains checks that produced an observation
// since the previous heartbeat (per design §4.2).
type LatencyEntry struct {
	LastObservedLatencyMs int       `json:"last_observed_latency_ms"`
	LastObservedAt        time.Time `json:"last_observed_at"`
}

// HeartbeatResponse: paused state, current threshold, etag the agent should
// hold. Checks is non-nil only when the etag changed (server included a
// fresh check list); the agent uses presence-of-checks as the cache-bust
// signal.
type HeartbeatResponse struct {
	ConfigEtag              string     `json:"config_etag"`
	Paused                  bool       `json:"paused"`
	FlapProtectionThreshold int        `json:"flap_protection_threshold"`
	RequestFullResync       bool       `json:"request_full_resync"`
	Checks                  []CheckDef `json:"checks,omitempty"`
}

// ShutdownRequest is what the agent posts on SIGTERM (per design §4.4).
// Best-effort — the agent does not retry; a missed /shutdown gets picked
// up by the offline watchdog after 60s.
type ShutdownRequest struct {
	Reason string `json:"reason"` // "sigterm", etc.
}
