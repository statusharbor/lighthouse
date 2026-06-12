// Package transport handles HTTPS communication with the Status Harbor
// Console. It owns the URL, the auth header shape, the JSON contract, and
// retry policy. Everything else in the agent treats the Console as an
// abstract sink.
package transport

import "time"

// RegisterRequest is what the agent posts to /api/lighthouse/v1/register on
// startup. Per design §4.1: the lighthouse_id is NOT sent — server resolves
// it from the bound token.
//
// Runtime is "kubernetes" when the agent's discovery probe sees
// KUBERNETES_SERVICE_HOST, "bare_metal" otherwise. Drives the server's
// sticky-update of lighthouses.allow_multi_instance — see
// docs/victoriametrics/lighthause/PLAN.md §1.3. Empty value (which would
// only come from an old agent that doesn't know about this field) is
// treated as "skip the sticky-update"; never lower a Lighthouse's flag
// based on an empty runtime.
type RegisterRequest struct {
	AgentVersion  string `json:"agent_version"`
	AgentHostname string `json:"agent_hostname"`
	Runtime       string `json:"runtime,omitempty"`
}

// HostMetricsConfig is the optional /register response field that gates the
// host-metrics collector (design §3.1). Three states the agent must honor:
//
//   - nil pointer (field omitted) — plan does not support metrics. Never collect.
//   - {Enabled: false}             — plan supports it but team paused. Stop now.
//   - {Enabled: true, …}           — collect every IntervalSeconds.
//
// Distinct from absence-of-field because an already-running collector needs an
// explicit "stop" signal rather than treating a missing field as "no change".
// Older Console builds simply omit the field and older agents ignore it
// (LIGHTHOUSE_API.md v1-stability rule: new optional fields don't bump v).
type HostMetricsConfig struct {
	Enabled         bool `json:"enabled"`
	IntervalSeconds int  `json:"interval_seconds"`
}

// RegisterResponse is what the Console returns from /register. Carries the
// per-agent operating parameters (heartbeat cadence, flap threshold) plus
// the initial check set.
type RegisterResponse struct {
	LighthouseID             string             `json:"lighthouse_id"`
	Name                     string             `json:"name"`
	Host                     string             `json:"host"`
	Paused                   bool               `json:"paused"`
	HeartbeatIntervalSeconds int                `json:"heartbeat_interval_seconds"`
	FlapProtectionThreshold  int                `json:"flap_protection_threshold"`
	ConfigEtag               string             `json:"config_etag"`
	Checks                   []CheckDef         `json:"checks"`
	HostMetrics              *HostMetricsConfig `json:"host_metrics,omitempty"`
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
	Type               string           `json:"type"` // http | https | tcp | udp | ssl | dns
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
	// DNS-only fields. DNSRecordType defaults to "A" when empty;
	// DNSExpectedIPs are the expected resolved value(s) (any record type,
	// not just IPs despite the name); DNSResolver is an optional explicit
	// resolver `host` or `host:port` (default port 53).
	DNSRecordType  string   `json:"dns_record_type,omitempty"`
	DNSExpectedIPs []string `json:"dns_expected_ips,omitempty"`
	DNSResolver    string   `json:"dns_resolver,omitempty"`
}

// HeartbeatInterval converts the response's seconds field to a Duration.
func (r *RegisterResponse) HeartbeatInterval() time.Duration {
	return time.Duration(r.HeartbeatIntervalSeconds) * time.Second
}

// EventsRequest is what the agent posts to /api/lighthouse/v1/events.
// SyncKind labels the batch:
//   - ""          — ordinary state transitions (prev_state known)
//   - "initial"   — agent boot, every check observed for the first time
//   - "resync"    — server requested via request_full_resync=true
//   - "new_check" — agent self-syncing checks added post-startup
//
// Per design §3.2 / §4.3.
type EventsRequest struct {
	SyncKind string       `json:"sync_kind,omitempty"`
	Events   []EventInput `json:"events"`
}

// EventInput is one state transition. PrevState is nil on initial-sync rows
// (server treats prev_state=NULL specially per Interpretation B).
type EventInput struct {
	CheckID         string    `json:"check_id"`
	PrevState       *string   `json:"prev_state"`
	NewState        string    `json:"new_state"` // "up" | "down"
	ResponseTimeMs  *int      `json:"response_time_ms,omitempty"`
	StatusCode      *int      `json:"status_code,omitempty"`
	ErrorMessage    *string   `json:"error_message,omitempty"`
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
	AgentVersion   string                     `json:"agent_version"`
	ConfigEtag     string                     `json:"config_etag,omitempty"`
	CheckLatencies map[string]LatencyEntry    `json:"check_latencies,omitempty"`
	CertExpiry     map[string]CertExpiryEntry `json:"cert_expiry,omitempty"`
	// NodeName identifies which node this agent pod is running on (or
	// the host's hostname on bare-metal). Drives the Console's
	// lighthouse_active_agents table — one row per (lighthouse, node)
	// for per-pod liveness in multi-instance Lighthouses. Empty when
	// the agent can't determine its node name; Console treats that as
	// "skip the per-node tracking" (bare-metal single-instance flow
	// keeps working).
	NodeName string `json:"node_name,omitempty"`
}

// LatencyEntry is a sparse per-check latency snapshot included in the
// heartbeat. The map only contains checks that produced an observation
// since the previous heartbeat (per design §4.2).
type LatencyEntry struct {
	LastObservedLatencyMs int       `json:"last_observed_latency_ms"`
	LastObservedAt        time.Time `json:"last_observed_at"`
}

// CertExpiryEntry is a sparse per-check TLS certificate-expiry snapshot
// included in the heartbeat, mirroring LatencyEntry. The map is keyed by
// check id and only contains ssl checks that read a leaf certificate since
// the previous heartbeat. DaysToExpiry is floor((NotAfter - now) / 24h) and
// may be 0 or negative for an expired cert. The pre-expiry warning threshold
// is owned by the Console — the agent applies no threshold logic.
type CertExpiryEntry struct {
	DaysToExpiry int       `json:"days_to_expiry"`
	ObservedAt   time.Time `json:"observed_at"`
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

// DiscoverySnapshotItem is one entry in the agent's snapshot payload.
// Covers both Ingress and Service resources; `Kind` is the
// discriminator. Path is meaningful for ingresses, Port for services.
type DiscoverySnapshotItem struct {
	Kind         string `json:"kind"` // "ingress" | "service"
	Namespace    string `json:"namespace"`
	ResourceName string `json:"resource_name"`
	Host         string `json:"host"`
	Path         string `json:"path,omitempty"`
	Port         int    `json:"port,omitempty"`
	Protocol     string `json:"protocol"` // http|https|tcp|udp
}

// DiscoverySnapshotRequest is what the agent posts to
// /api/lighthouse/v1/discoveries. Snapshot=true means the items list
// is authoritative for this lighthouse: server deletes (or marks
// source_missing if adopted) any rows not in the set.
type DiscoverySnapshotRequest struct {
	Snapshot bool                    `json:"snapshot"`
	Items    []DiscoverySnapshotItem `json:"items"`
}

// DiscoverySnapshotResponse is the server's ack with the count it
// persisted.
type DiscoverySnapshotResponse struct {
	Count int `json:"count"`
}
