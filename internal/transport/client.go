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
	"strconv"
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

// newAgentTransport returns a pinned http.Transport so future
// std-lib bumps don't change behaviour silently and so we own the
// assumptions we make about the Console's behaviour.
//
// Stage budgets — pre-flight tighter than the wall-clock 30s above:
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
func newAgentTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 256 * 1024,
		IdleConnTimeout:        60 * time.Second,
		MaxIdleConnsPerHost:    4, // small fleet of concurrent
		// goroutines (heartbeat, events, host metrics, discovery
		// snapshot) all hitting one Console host. 4 keeps the
		// pool warm without spawning excess sockets.
		ForceAttemptHTTP2: true,
	}
}

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
func (c *Client) Heartbeat(ctx context.Context, req HeartbeatRequest) (*HeartbeatResponse, error) {
	var out HeartbeatResponse
	if err := c.postJSON(ctx, "/api/lighthouse/v1/heartbeat", req, &out, http.StatusOK); err != nil {
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

// Shutdown notifies the Console that the agent is exiting cleanly so the
// offline watchdog skips it during the 60s grace window. Best-effort —
// caller does not retry. Returns ErrLighthouseGone on 410 like the others.
func (c *Client) Shutdown(ctx context.Context, req ShutdownRequest) error {
	return c.postJSON(ctx, "/api/lighthouse/v1/shutdown", req, nil, http.StatusNoContent)
}

// postJSON is the shared transport core: marshal, POST with Bearer auth,
// branch on status (410 → ErrLighthouseGone, expectedStatus → decode,
// other → error with body for diagnostics).
func (c *Client) postJSON(ctx context.Context, path string, in any, out any, expectedStatus int) error {
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.token)
	httpReq.Header.Set("Content-Type", "application/json")
	c.setInstanceHeaders(httpReq)

	resp, err := c.httpc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("post %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusGone || resp.StatusCode == http.StatusUnauthorized {
		// 410: lighthouse soft-deleted (legacy contract).
		// 401: lighthouse hard-deleted — the cascade dropped our api_token,
		// so the next call's bearer no longer resolves. Either way the
		// agent should stop running checks for a non-existent target.
		return ErrLighthouseGone
	}
	if resp.StatusCode != expectedStatus {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s: HTTP %d: %s", path, resp.StatusCode, string(body))
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode %s response: %w", path, err)
	}
	return nil
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
