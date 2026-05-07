package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is the agent's HTTPS client to the Console. The base URL is the
// hardcoded production ingress in real deployments; tests inject an
// httptest.Server URL via NewClient.
type Client struct {
	baseURL string
	token   string
	httpc   *http.Client
}

// ErrLighthouseGone signals that the Console says this agent's lighthouse
// no longer exists. Returned on:
//   - 410 Gone — the legacy soft-delete contract.
//   - 401 Unauthorized — the current hard-delete contract; deleting a
//     lighthouse cascades the bound api_token via FK, so the next agent
//     call's bearer no longer resolves.
// The agent must exit cleanly in either case.
var ErrLighthouseGone = errors.New("lighthouse has been deleted")

// NewClient builds a Client. baseURL is the Console root — for production
// this is `https://lighthouse.statusharbor.io`; tests pass an httptest URL.
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		httpc: &http.Client{
			Timeout: 30 * time.Second,
		},
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
