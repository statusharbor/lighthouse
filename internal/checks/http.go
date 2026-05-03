package checks

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPCheck performs an HTTP or HTTPS request and validates the response
// against expected status code and (optionally) an expected substring in
// the body. Both http:// and https:// targets go through this single
// executor — the URL scheme determines transport.
type HTTPCheck struct{}

// HTTPParams is what the executor needs from the agent's CheckDefinition.
// Empty/zero fields take sensible defaults: Method=GET,
// ExpectedStatusCode=200.
type HTTPParams struct {
	URL                string
	Method             string
	Timeout            time.Duration
	ExpectedStatusCode int

	// KeywordCheck and KeywordPresent: when KeywordCheck is non-empty,
	// the response body must (KeywordPresent=true) or must not
	// (KeywordPresent=false) contain the substring.
	KeywordCheck   string
	KeywordPresent bool

	// SkipTLSVerify: skip certificate validation. Off by default —
	// production HTTPS checks should NOT skip verification.
	SkipTLSVerify bool

	// ReadBodyLimit caps the bytes we'll pull off the wire for keyword
	// matching. Defaults to 1 MB so a runaway response can't OOM the
	// agent.
	ReadBodyLimit int64
}

const defaultReadBodyLimit = 1 << 20 // 1 MB

func (HTTPCheck) Run(ctx context.Context, p HTTPParams) Result {
	if p.Method == "" {
		p.Method = http.MethodGet
	}
	if p.ExpectedStatusCode == 0 {
		p.ExpectedStatusCode = 200
	}
	if p.ReadBodyLimit <= 0 {
		p.ReadBodyLimit = defaultReadBodyLimit
	}

	// Per-call client so the TLS verify setting + timeout don't leak
	// across concurrent checks.
	client := &http.Client{
		Timeout: p.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: p.SkipTLSVerify},
		},
	}

	req, err := http.NewRequestWithContext(ctx, p.Method, p.URL, nil)
	if err != nil {
		return Result{
			Up:           false,
			ErrorMessage: fmt.Sprintf("build request: %s", err.Error()),
		}
	}
	req.Header.Set("User-Agent", "Lighthouse-Agent")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Result{
			Up:             false,
			ResponseTimeMs: msSince(start),
			ErrorMessage:   fmt.Sprintf("request failed: %s", err.Error()),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != p.ExpectedStatusCode {
		// Drain body so the connection can be reused (bounded read).
		_, _ = io.CopyN(io.Discard, resp.Body, p.ReadBodyLimit)
		return Result{
			Up:             false,
			ResponseTimeMs: msSince(start),
			StatusCode:     resp.StatusCode,
			ErrorMessage:   fmt.Sprintf("status %d, want %d", resp.StatusCode, p.ExpectedStatusCode),
		}
	}

	if p.KeywordCheck != "" {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, p.ReadBodyLimit))
		contains := strings.Contains(string(body), p.KeywordCheck)
		switch {
		case p.KeywordPresent && !contains:
			return Result{
				Up:             false,
				ResponseTimeMs: msSince(start),
				StatusCode:     resp.StatusCode,
				ErrorMessage:   fmt.Sprintf("keyword %q not found in body", p.KeywordCheck),
			}
		case !p.KeywordPresent && contains:
			return Result{
				Up:             false,
				ResponseTimeMs: msSince(start),
				StatusCode:     resp.StatusCode,
				ErrorMessage:   fmt.Sprintf("keyword %q unexpectedly present", p.KeywordCheck),
			}
		}
	}

	return Result{
		Up:             true,
		ResponseTimeMs: msSince(start),
		StatusCode:     resp.StatusCode,
	}
}
