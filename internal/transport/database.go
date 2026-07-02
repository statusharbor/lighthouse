package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// DatabaseSnapshotsPath is the ingest endpoint for database introspection.
const DatabaseSnapshotsPath = "/api/lighthouse/v1/db-snapshots"

// ErrDatabaseGone signals the Console no longer knows this database_id
// (deleted / reassigned). Distinct from ErrLighthouseGone: only this one
// cluster should be dropped, the agent keeps running everything else.
var ErrDatabaseGone = errors.New("database gone")

// SendDatabaseSnapshots ships one cluster's snapshot. Not routed through
// postJSON because a 410 here means "drop this database_id", whereas
// postJSON treats 410 as "the whole lighthouse is gone". No disk buffer:
// a dropped snapshot just resends current state next tick (host-metrics
// model, not the events model).
func (c *Client) SendDatabaseSnapshots(ctx context.Context, req DBSnapshotRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal db snapshot: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+DatabaseSnapshotsPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build db snapshot request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.token)
	httpReq.Header.Set("Content-Type", "application/json")
	c.setInstanceHeaders(httpReq)

	resp, err := c.httpc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("post db snapshot: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusGone:
		return ErrDatabaseGone
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrLighthouseGone
	case resp.StatusCode != http.StatusAccepted:
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("db snapshot: HTTP %d: %s", resp.StatusCode, string(b))
	}
	return nil
}
