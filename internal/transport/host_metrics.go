// Real implementation of the host-metrics Sender contract (design §3.1, §3.2).
//
// What landed here:
//   - HostMetricsPath constant — flat token-derived agent endpoint.
//   - HostSample wire type — kept in transport (not agent) to break the
//     agent↔transport import cycle.
//   - HostMetricsSender interface.
//   - HTTPHostMetricsSender — Prometheus-remote_write + snappy + Bearer-token
//     POST to the Console relay. Reuses the existing transport.Client base
//     URL + auth header convention.
//   - NoopSender — kept for the runner-not-yet-fully-wired path.
//
// Backoff / disk-buffer integration: this Sender does NOT implement retry. It
// returns the error so the runner (which already owns the existing 1s/4s/16s
// retry ladder + disk buffer for events) can route failed batches the same
// way. The relay's 429 (rate-cap) and 413 (split-batch) shapes ride through
// transparently via err message classification.
package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/klauspost/compress/snappy"
)

// HostMetricsPath is the agent-side endpoint for the host-metrics ingest path.
// Flat + token-derived (design §3.5a): the agent never carries its lighthouse
// id / team / account on the path — the server resolves them from the bound
// scoped token. Identical shape to /register, /heartbeat, /events.
const HostMetricsPath = "/api/lighthouse/v1/host-metrics"

// HostSample is one observation. Labels carry metric-native dimensions (CPU
// core, mount, network interface, …). Under thin-proxy the Console does NOT
// stamp tenant labels server-side, so the agent's labels are what reach
// vminsert as-is — keep them minimal. Timestamp is unix-millis.
//
// Lives in transport (not agent) because it's the wire shape: putting it in
// agent created an import cycle when transport's HostMetricsSender wanted to
// take a batch of samples.
type HostSample struct {
	Name      string
	Labels    map[string]string
	Value     float64
	Timestamp int64
}

// HostMetricsSender forwards one batch of HostSample to the Console. The
// runner calls Emit on its own goroutine; implementations must be safe to call
// while a prior call is still in flight (the obvious shape is a mutex around
// the HTTP POST or a single-flight semaphore).
type HostMetricsSender interface {
	Emit(ctx context.Context, samples []HostSample) error
}

// HTTPHostMetricsSender posts snappy-compressed Prometheus-remote_write
// WriteRequest bodies to the Console relay. Owns its own *http.Client but
// shares baseURL + token shape with the existing transport.Client (caller
// passes the same values to NewHTTPHostMetricsSender).
type HTTPHostMetricsSender struct {
	baseURL      string
	token        string
	lighthouseID string
	hostname     string
	// Per-instance identity. Mirrors transport.Client — keeps the host-
	// metrics path subject to the same single-active-instance claim +
	// behavioural signals on the Console. Empty instanceID disables the
	// header (Console then doesn't enforce).
	instanceID       string
	processStartedAt time.Time
	httpc            *http.Client
	scratch          []byte // reused encode buffer per call site; nil-safe
}

// NewHTTPHostMetricsSender constructs a Sender wired to the same Console as
// the existing transport.Client. Use the same baseURL + token so a single
// agent process speaks to one Console with one identity.
//
// lighthouseID stamps a `lighthouse_id="<uuid>"` label on every emitted
// sample. The relay is a thin proxy that does NOT decode and re-stamp
// labels (handler_lighthouse_host_metrics.go header), so any label that
// scopes-to-this-agent has to come from the agent itself. Without it, the
// Console UI's "filter by lighthouse" path returns empty.
//
// hostname stamps a `host="<os.Hostname()>"` label on every sample that
// doesn't already carry one. Collectors that emit per-mount or per-device
// metrics already attach `mount` / `device` but don't always attach
// `host` — this fills the gap so the Console UI can render
// "lighthouse-name(hostname)" labels uniformly. Empty hostname is a noop.
func NewHTTPHostMetricsSender(baseURL, token, lighthouseID, hostname, instanceID string, httpc *http.Client) *HTTPHostMetricsSender {
	if httpc == nil {
		httpc = &http.Client{Timeout: defaultHostMetricsTimeout}
	}
	return &HTTPHostMetricsSender{
		baseURL:          baseURL,
		token:            token,
		lighthouseID:     lighthouseID,
		hostname:         hostname,
		instanceID:       instanceID,
		// UTC — only ever used as the reference point for time.Since(),
		// so the timezone is mathematically irrelevant, but storing UTC
		// keeps any future log/serialise call timezone-clean.
		processStartedAt: time.Now().UTC(),
		httpc:            httpc,
	}
}

// defaultHostMetricsTimeout matches transport.Client at client.go:39 — same
// 30s ceiling for any request to the Console. Previously this was expressed
// as `30 * defaultTimeoutMultiplier` with a unitless multiplier; without the
// `time.Second` unit Go coerced the untyped int to time.Duration as
// nanoseconds, giving a 30ns timeout (so every Emit failed with "context
// deadline exceeded"). Explicit units fix the bug at the source.
const defaultHostMetricsTimeout = 30 * time.Second

// Emit encodes the batch to remote_write, snappy-compresses, and POSTs to the
// relay. Returns nil on 2xx, an error on anything else. The runner's existing
// retry/buffer layer treats this Sender like any other transport call.
//
// Error classification:
//   - 4xx (typically 429 rate-cap or 413 split-batch) — Err message includes
//     the upstream status; the runner can match on it to decide whether to
//     drop, back off, or split.
//   - 5xx / network — Err carries the message; the runner retries on its
//     ladder.
//   - 503 specifically signals "relay not configured" (VM_INSERT_URL unset on
//     the Console). Caller may choose a longer back-off than the 1s/4s/16s
//     default in that case.
func (s *HTTPHostMetricsSender) Emit(ctx context.Context, samples []HostSample) error {
	if len(samples) == 0 {
		return nil
	}

	// Stamp lighthouse_id + host on every sample so the relay-side query
	// proxy can filter "show me only this agent's metrics" and the
	// Console UI can render "lighthouse-name(hostname)" labels uniformly.
	// The thin relay doesn't decode + re-stamp; both labels have to be on
	// the wire here. Done at Emit time (not in collectors) so the
	// platform-wide collector API stays oblivious to identity — the
	// sender owns the agent identity.
	if s.lighthouseID != "" || s.hostname != "" {
		stamped := make([]HostSample, len(samples))
		for i, sm := range samples {
			labels := make(map[string]string, len(sm.Labels)+2)
			for k, v := range sm.Labels {
				labels[k] = v
			}
			if s.lighthouseID != "" {
				labels["lighthouse_id"] = s.lighthouseID
			}
			// Don't overwrite a collector-supplied host (none today, but
			// future-proof: a multi-host collector could attach a more
			// specific value than os.Hostname()).
			if s.hostname != "" {
				if _, exists := labels["host"]; !exists {
					labels["host"] = s.hostname
				}
			}
			sm.Labels = labels
			stamped[i] = sm
		}
		samples = stamped
	}

	// Reset scratch + encode. EncodeWriteRequest appends, so reset to length
	// zero (keeping capacity) before each call to avoid one allocation per
	// batch.
	s.scratch = EncodeWriteRequest(s.scratch[:0], samples)

	// snappy-encode in a fresh buffer — Encode returns a length-prefixed slice
	// that needs its own backing array (don't alias scratch).
	compressed := snappy.Encode(nil, s.scratch)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+HostMetricsPath, bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("build host-metrics request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	// Required by every remote_write 1.x receiver including vminsert.
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	// Single-active-instance claim + behavioral signal headers — see
	// transport.Client.setInstanceHeaders and the Console middleware
	// at internal/api/middleware.go.
	if s.instanceID != "" {
		req.Header.Set("X-Lighthouse-Instance-Id", s.instanceID)
	}
	if !s.processStartedAt.IsZero() {
		secs := int64(time.Since(s.processStartedAt).Seconds())
		if secs < 0 {
			secs = 0
		}
		req.Header.Set("X-Lighthouse-Process-Uptime", strconv.FormatInt(secs, 10))
	}

	resp, err := s.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("post host-metrics: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK:
		return nil
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return fmt.Errorf("host-metrics relay %d: %s", resp.StatusCode, string(body))
	}
}

// NewNoopSender returns a HostMetricsSender that drops samples on the floor.
// Kept as a fallback for runtimes where the agent should NOT actually emit —
// e.g. dev or CI runs where there's no Console. The runner picks Noop when
// the /register response omits HostMetrics (Phase 2 contract: nil = plan
// doesn't support metrics, never collect).
func NewNoopSender() HostMetricsSender {
	return noopSender{}
}

type noopSender struct{}

func (noopSender) Emit(_ context.Context, _ []HostSample) error { return nil }
