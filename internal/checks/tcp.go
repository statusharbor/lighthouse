// Package checks contains the protocol-level executors for the agent.
//
// These were re-implemented fresh in this public repo rather than copied
// from the closed Console — the Console's checkers are entangled with its
// internal proxy/region routing, which doesn't apply to a single-location
// agent. The protocol-level cores are short enough that fresh
// implementation was clearer than sanitization.
package checks

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TCPCheck dials a TCP endpoint, optionally sends a payload, optionally
// asserts a substring is present in the response. Returns up/down + latency.
//
// Target conventions (from the Console's CheckDefinition):
//   - URL field carries `host` or `host:port` or `tcp://host:port`.
//   - Method/ExpectedStatusCode are unused for TCP.
//   - KeywordCheck (when set) is treated as the expected-substring sentinel
//     and KeywordPresent toggles "must contain" vs "must NOT contain".
type TCPCheck struct{}

// TCPParams parses the agent's CheckDefinition into the few fields TCP cares
// about. Defined here so this file stays free of agent-package imports —
// keeps the dependency arrow checks → (nothing else) for cleanliness.
type TCPParams struct {
	Host           string
	Port           int
	Timeout        time.Duration
	SendPayload    string // optional
	ExpectContains string // optional substring assertion
}

// Result is what every executor returns. Mirrors the agent's CheckObservation
// at the field level — the agent translates between them at boundaries to
// avoid pulling agent types into the checks package.
type Result struct {
	Up             bool
	ResponseTimeMs int
	StatusCode     int    // HTTP only; 0 for TCP/UDP
	ErrorMessage   string // empty on Up=true
	// CertDaysToExpiry is set only by the SSL executor, whenever a leaf
	// certificate was read (valid OR expired). nil for every other check
	// type. floor((NotAfter - now) / 24h); may be 0 or negative.
	CertDaysToExpiry *int
}

// Run dials the target, applies the optional payload + response assertion,
// returns the outcome. Honors ctx cancellation throughout.
func (TCPCheck) Run(ctx context.Context, p TCPParams) Result {
	addr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	d := net.Dialer{Timeout: p.Timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Result{
			Up:             false,
			ResponseTimeMs: msSince(start),
			ErrorMessage:   fmt.Sprintf("dial tcp %s: %s", addr, err.Error()),
		}
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(p.Timeout)
	_ = conn.SetDeadline(deadline)

	if p.SendPayload != "" {
		if _, err := conn.Write([]byte(p.SendPayload)); err != nil {
			return Result{
				Up:             false,
				ResponseTimeMs: msSince(start),
				ErrorMessage:   fmt.Sprintf("write tcp %s: %s", addr, err.Error()),
			}
		}
	}

	if p.ExpectContains != "" {
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		rtt := msSince(start)
		if err != nil {
			return Result{
				Up:             false,
				ResponseTimeMs: rtt,
				ErrorMessage:   fmt.Sprintf("read tcp %s: %s", addr, err.Error()),
			}
		}
		if !strings.Contains(string(buf[:n]), p.ExpectContains) {
			return Result{
				Up:             false,
				ResponseTimeMs: rtt,
				ErrorMessage:   fmt.Sprintf("expected substring not in response (read %d bytes)", n),
			}
		}
	}
	return Result{Up: true, ResponseTimeMs: msSince(start)}
}

// ParseTCPTarget extracts host+port from a target string. Accepts
// "host:port", "tcp://host:port", or "host" with a separate port. The
// port-in-URL form is parsed via url.Parse only when an explicit `//`
// scheme prefix is present — `host:port` (no scheme) is too easy to
// misread as `<scheme>:<opaque>` otherwise.
func ParseTCPTarget(rawURL string, fallbackPort int) (host string, port int, err error) {
	s := strings.TrimSpace(rawURL)
	if strings.Contains(s, "://") {
		u, perr := url.Parse(s)
		if perr != nil {
			return "", 0, fmt.Errorf("invalid url: %w", perr)
		}
		host = u.Hostname()
		if u.Port() != "" {
			port, _ = strconv.Atoi(u.Port())
		}
	} else {
		host = s
		if h, p, splitErr := net.SplitHostPort(s); splitErr == nil {
			host = h
			port, _ = strconv.Atoi(p)
		}
	}
	if port == 0 {
		port = fallbackPort
	}
	if host == "" {
		return "", 0, fmt.Errorf("empty host")
	}
	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %d", port)
	}
	return host, port, nil
}

func msSince(t time.Time) int {
	return int(time.Since(t) / time.Millisecond)
}
