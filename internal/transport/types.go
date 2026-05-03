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

// CheckDef is the agent-side view of a check definition. Mirrors the JSON
// shape returned by the Console; not every field applies to every check
// type (see Type).
type CheckDef struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`           // http | https | tcp | udp
	Name               string `json:"name"`
	URL                string `json:"url,omitempty"`
	Method             string `json:"method,omitempty"`
	ExpectedStatusCode int    `json:"expected_status_code,omitempty"`
	IntervalSeconds    int    `json:"interval_seconds"`
	TimeoutSeconds     int    `json:"timeout_seconds"`
	KeywordCheck       string `json:"keyword_check,omitempty"`
	KeywordPresent     bool   `json:"keyword_present,omitempty"`
}

// HeartbeatInterval converts the response's seconds field to a Duration.
func (r *RegisterResponse) HeartbeatInterval() time.Duration {
	return time.Duration(r.HeartbeatIntervalSeconds) * time.Second
}
