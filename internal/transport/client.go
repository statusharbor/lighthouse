package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Client is the agent's HTTPS client to the Console. The base URL is the
// hardcoded production ingress in real deployments; tests inject an
// httptest.Server URL via NewClient.
type Client struct {
	baseURL string
	token   string
	httpc   *http.Client

	// Per-instance identity. instanceID is a stable UUID persisted under
	// <DataDir>/instance.id; processStartedAt is set at NewClient and used
	// to compute X-Lighthouse-Process-Uptime on each request. Together
	// they drive the Console's single-active-instance claim + the
	// behavioral detection signals (source-IP change, uptime regression)
	// — see /api/lighthouse/v1/* middleware in status-harbor.
	instanceID       string
	processStartedAt time.Time

	// Channel-health telemetry from the most recent heartbeat, reported
	// on the NEXT heartbeat (see HeartbeatRequest.RTTMs). Written by
	// Heartbeat after each round-trip and read when the heartbeat loop
	// builds the next request. Both live on the same goroutine in
	// practice, but atomics keep a future health-endpoint reader safe.
	lastHeartbeatRTTMs       atomic.Int64
	lastHeartbeatClockSkewMs atomic.Int64
}

// RetryableStatusError is returned when the Console responds with a status
// the caller may retry after a delay: 429 (rate limited) or any 5xx. It
// carries the parsed Retry-After hint so the heartbeat loop can honour the
// server's requested pause instead of applying its own backoff. Other
// callers treat it as an ordinary error - the extra fields are inert unless
// inspected via errors.As.
type RetryableStatusError struct {
	Path       string
	StatusCode int
	// RetryAfter is the parsed Retry-After header (seconds or HTTP-date
	// form). Zero when the header was absent or unparseable.
	RetryAfter time.Duration
	Body       string
}

func (e *RetryableStatusError) Error() string {
	return fmt.Sprintf("%s: HTTP %d: %s", e.Path, e.StatusCode, e.Body)
}

// parseRetryAfter parses a Retry-After header value, which per RFC 7231 is
// either delta-seconds (an integer) or an HTTP-date. Returns 0 for an
// empty, negative or unparseable value.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// ErrLighthouseGone signals that the Console says this agent's lighthouse
// no longer exists. Returned on:
//   - 410 Gone — the legacy soft-delete contract.
//   - 401 Unauthorized — the current hard-delete contract; deleting a
//     lighthouse cascades the bound api_token via FK, so the next agent
//     call's bearer no longer resolves.
//
// The agent must exit cleanly in either case.
var ErrLighthouseGone = errors.New("lighthouse has been deleted")

// NewClient builds a Client. baseURL is the Console root — for production
// this is `https://lighthouse.statusharbor.io`; tests pass an httptest URL.
//
// instanceID is the stable per-install UUID from <DataDir>/instance.id;
// pass "" in tests or when callers don't want to participate in the
// single-active-instance claim (the Console treats empty as "don't
// enforce"). Process uptime is computed from time.Now() at NewClient,
// which matches the agent's process lifetime — the binary is restarted
// when the systemd / Windows service unit cycles.
func NewClient(baseURL, token, instanceID string) *Client {
	return &Client{
		baseURL:          baseURL,
		token:            token,
		instanceID:       instanceID,
		processStartedAt: time.Now().UTC(),
		httpc: &http.Client{
			// Whole-request budget. The transport-level timeouts
			// below carve it up into stage budgets so a stalled
			// peer at any single stage gives up quickly rather
			// than burning the full 30s.
			Timeout:   30 * time.Second,
			Transport: newAgentTransport(),
		},
	}
}

// maxIdleConnsPerConsole bounds the keepalive pool against one
// Console host. The agent's concurrent goroutines (heartbeat, events,
// host-metrics, discovery snapshot) all share it; 4 keeps the pool
// warm without spawning excess sockets.
const maxIdleConnsPerConsole = 4

// newAgentTransport returns a pinned http.Transport so future
// std-lib bumps don't change behaviour silently and so we own the
// assumptions we make about the Console's behaviour. Exported as
// NewAgentTransport so the host-metrics sender (separate *http.Client
// for the remote_write path) inherits the same stage budgets.
//
// Stage budgets — pre-flight tighter than the wall-clock 30s on the
// owning Client:
//
//   - Dial:                   5s  (DNS + TCP connect)
//   - TLS handshake:          5s  (verify the cert chain)
//   - Response headers:       10s (Console accepted bytes; awaiting
//                                  status + headers)
//   - Idle conn lifetime:     60s (matches the Console's typical
//                                  keepalive; avoids serving a
//                                  request through a half-closed
//                                  socket)
//
// MaxResponseHeaderBytes caps the headers section at 256 KiB so a
// pathological / malicious Console can't stream gigabytes of header
// at us before we notice. The body has its own io.Reader-level
// bound elsewhere; this is just the headers ceiling.
//
// HTTP/2 is force-attempted so a Console behind a Gateway / L7
// load balancer doesn't pay the per-request TCP + TLS cost.
func NewAgentTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 256 * 1024,
		IdleConnTimeout:        60 * time.Second,
		MaxIdleConnsPerHost:    maxIdleConnsPerConsole,
		ForceAttemptHTTP2:      true,
	}
}

// newAgentTransport is the package-internal alias preserved so existing
// callers don't need to change. New external callers (other transport
// types) should use the exported NewAgentTransport.
func newAgentTransport() *http.Transport { return NewAgentTransport() }

// Register performs the startup handshake. Per design §4.1 the agent
// reports its identity and the server returns the operating parameters
// plus the current check set.
//
// Returns ErrLighthouseGone on 410 so the caller can exit(0) cleanly
// instead of treating it as an auth failure.
func (c *Client) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	var out RegisterResponse
	if err := c.postJSON(ctx, "/api/lighthouse/v1/register", req, &out, http.StatusOK); err != nil {
		return nil, err
	}
	return &out, nil
}

// SendEvents posts a batch of state transitions (initial-sync dump or
// otherwise). The Console is allowed to dedup, so the response's
// `received` count may be less than len(req.Events).
func (c *Client) SendEvents(ctx context.Context, req EventsRequest) (*EventsResponse, error) {
	var out EventsResponse
	if err := c.postJSON(ctx, "/api/lighthouse/v1/events", req, &out, http.StatusAccepted); err != nil {
		return nil, err
	}
	return &out, nil
}

// Heartbeat posts liveness + an optional latency rollup. The Console may
// echo a fresh check set (via Checks) when the etag changed. Per design
// §4.2 there is **no retry** at this layer — a failed heartbeat is dropped
// and the next 15s tick is the retry.
// SendEBPFEvents posts one batch of eBPF collector events. No retry here:
// the caller's batcher keeps the batch and retries on its next flush.
func (c *Client) SendEBPFEvents(ctx context.Context, req EBPFEventsRequest) (*EBPFEventsResponse, error) {
	var resp EBPFEventsResponse
	if err := c.postJSON(ctx, "/api/lighthouse/v1/ebpf/events", req, &resp, http.StatusAccepted); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Heartbeat(ctx context.Context, req HeartbeatRequest) (*HeartbeatResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	var out HeartbeatResponse
	serverDate, rtt, err := c.doJSONMeta(ctx, http.MethodPost, "/api/lighthouse/v1/heartbeat", body, &out, http.StatusOK)
	// Record channel-health telemetry for the NEXT beat's report, even on
	// error - a slow or failed beat's RTT is still a useful signal. Skew
	// needs the server Date header, which a failed proxy hop may omit; keep
	// the prior skew reading in that case rather than zeroing it.
	c.lastHeartbeatRTTMs.Store(rtt.Milliseconds())
	if !serverDate.IsZero() {
		c.lastHeartbeatClockSkewMs.Store(time.Since(serverDate).Milliseconds())
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// LastHeartbeatRTTMs returns the round-trip time of the most recent
// heartbeat in milliseconds (0 before the first beat). The heartbeat loop
// reads it while building the next request, so the reported value always
// lags one beat - which is the "previous heartbeat" semantics the Console
// expects.
func (c *Client) LastHeartbeatRTTMs() int64 { return c.lastHeartbeatRTTMs.Load() }

// LastHeartbeatClockSkewMs returns (agent clock - server Date) at the most
// recent heartbeat response, in milliseconds. 0 before the first beat or
// when no response carried a parseable Date header yet.
func (c *Client) LastHeartbeatClockSkewMs() int64 { return c.lastHeartbeatClockSkewMs.Load() }

// Config fetches the cold-path config bundle (GET /config). The agent
// calls it only when the relevant config etag from its last heartbeat
// differs from its cached one - the heartbeat itself carries just the etag
// + the cheap databases-enabled flag, not the cluster list or node DSNs.
//
// sections narrows the response to the named sections via ?sections=a,b
// (#11 per-section etags). The agent only fetches the databases section, so
// a monitor edit - which bumps the checks section but not databases - never
// forces the heavy DSN payload back over the wire. Empty sections requests
// the whole bundle (older-console behaviour).
func (c *Client) Config(ctx context.Context, sections ...string) (*ConfigResponse, error) {
	path := "/api/lighthouse/v1/config"
	if len(sections) > 0 {
		q := url.Values{}
		q.Set("sections", strings.Join(sections, ","))
		path += "?" + q.Encode()
	}
	var out ConfigResponse
	if err := c.getJSON(ctx, path, &out, http.StatusOK); err != nil {
		return nil, err
	}
	return &out, nil
}

// SendDiscoveries posts a snapshot of discovered Ingress endpoints.
// Items are reconciled server-side per lighthouse: rows not in the
// snapshot are deleted (or marked source_missing if adopted). The
// caller treats errors as non-fatal — a missed snapshot just gets
// resent on the next informer event or relist.
func (c *Client) SendDiscoveries(ctx context.Context, req DiscoverySnapshotRequest) (*DiscoverySnapshotResponse, error) {
	var out DiscoverySnapshotResponse
	if err := c.postJSON(ctx, "/api/lighthouse/v1/discoveries", req, &out, http.StatusOK); err != nil {
		return nil, err
	}
	return &out, nil
}

// SendK8sAddresses replaces the Lighthouse's cluster address map.
func (c *Client) SendK8sAddresses(ctx context.Context, req K8sAddressesRequest) error {
	return c.postJSON(ctx, "/api/lighthouse/v1/k8s-addresses", req, nil, http.StatusNoContent)
}

// Shutdown notifies the Console that the agent is exiting cleanly so the
// offline watchdog skips it during the 60s grace window. Best-effort —
// caller does not retry. Returns ErrLighthouseGone on 410 like the others.
func (c *Client) Shutdown(ctx context.Context, req ShutdownRequest) error {
	return c.postJSON(ctx, "/api/lighthouse/v1/shutdown", req, nil, http.StatusNoContent)
}

// postJSON marshals the body and POSTs it. Thin wrapper over doJSON.
func (c *Client) postJSON(ctx context.Context, path string, in any, out any, expectedStatus int) error {
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	return c.doJSON(ctx, http.MethodPost, path, body, out, expectedStatus)
}

// getJSON GETs path (no request body) and decodes the response. Used for the
// cold-path /config fetch.
func (c *Client) getJSON(ctx context.Context, path string, out any, expectedStatus int) error {
	return c.doJSON(ctx, http.MethodGet, path, nil, out, expectedStatus)
}

// doJSON is the shared transport core: send with Bearer auth, branch on
// status (410/401 → ErrLighthouseGone, expectedStatus → decode, other →
// error with body for diagnostics). body nil means no request payload.
func (c *Client) doJSON(ctx context.Context, method, path string, body []byte, out any, expectedStatus int) error {
	_, _, err := c.doJSONMeta(ctx, method, path, body, out, expectedStatus)
	return err
}

// doJSONMeta is doJSON plus the response metadata the heartbeat path needs
// for its channel-health report: the round-trip duration and the parsed
// server `Date` header. serverDate is the zero time when the response
// carried no parseable Date. rtt is always set once the request left the
// wire (even on a non-2xx or a decode error), so a failed beat can still
// report how long it took.
//
// On a retryable status (429 / 5xx) it returns a *RetryableStatusError so
// the heartbeat loop can honour a Retry-After hint; all other non-expected
// statuses return the same plain diagnostic error as before.
func (c *Client) doJSONMeta(ctx context.Context, method, path string, body []byte, out any, expectedStatus int) (serverDate time.Time, rtt time.Duration, err error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	c.setInstanceHeaders(httpReq)

	start := time.Now()
	resp, err := c.httpc.Do(httpReq)
	rtt = time.Since(start)
	if err != nil {
		return time.Time{}, rtt, fmt.Errorf("post %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if d := resp.Header.Get("Date"); d != "" {
		if parsed, perr := http.ParseTime(d); perr == nil {
			serverDate = parsed
		}
	}

	if resp.StatusCode == http.StatusGone || resp.StatusCode == http.StatusUnauthorized {
		// 410: lighthouse soft-deleted (legacy contract).
		// 401: lighthouse hard-deleted — the cascade dropped our api_token,
		// so the next call's bearer no longer resolves. Either way the
		// agent should stop running checks for a non-existent target.
		return serverDate, rtt, ErrLighthouseGone
	}
	if resp.StatusCode != expectedStatus {
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return serverDate, rtt, &RetryableStatusError{
				Path:       path,
				StatusCode: resp.StatusCode,
				RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
				Body:       string(respBody),
			}
		}
		return serverDate, rtt, fmt.Errorf("%s: HTTP %d: %s", path, resp.StatusCode, string(respBody))
	}
	if out == nil {
		return serverDate, rtt, nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return serverDate, rtt, fmt.Errorf("decode %s response: %w", path, err)
	}
	return serverDate, rtt, nil
}

// setInstanceHeaders stamps the per-instance claim + soft-signal headers
// the Console's lighthouse-token middleware reads:
//
//	X-Lighthouse-Instance-Id      — stable UUID, drives the single-active
//	                                claim. Empty means "agent didn't
//	                                participate in the claim"; Console
//	                                treats that as compatible with any
//	                                held claim and skips enforcement.
//	X-Lighthouse-Process-Uptime   — integer seconds since process start.
//	                                Used by the Console to detect a
//	                                non-monotonic uptime (token copied
//	                                to a freshly-booted machine starts
//	                                the counter over).
func (c *Client) setInstanceHeaders(req *http.Request) {
	if c.instanceID != "" {
		req.Header.Set("X-Lighthouse-Instance-Id", c.instanceID)
	}
	if !c.processStartedAt.IsZero() {
		secs := int64(time.Since(c.processStartedAt).Seconds())
		if secs < 0 {
			secs = 0
		}
		req.Header.Set("X-Lighthouse-Process-Uptime", strconv.FormatInt(secs, 10))
	}
}
