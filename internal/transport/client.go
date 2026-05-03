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

// ErrLighthouseGone signals that the Console returned 410 — the lighthouse
// has been soft-deleted. The agent must exit cleanly. Per design §4.1.
var ErrLighthouseGone = errors.New("lighthouse has been deleted (410 Gone)")

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
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/lighthouse/v1/register", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("post register: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		var out RegisterResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return nil, fmt.Errorf("decode register response: %w", err)
		}
		return &out, nil
	case http.StatusGone:
		return nil, ErrLighthouseGone
	default:
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("register: HTTP %d: %s", resp.StatusCode, string(body))
	}
}
