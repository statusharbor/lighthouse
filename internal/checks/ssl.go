package checks

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"
)

// SSLCheck monitors TLS certificate expiry on an endpoint. Unlike the HTTP
// checker it does NOT verify the chain: internal Ingress certs are commonly
// issued by a private/internal CA, so a verifying dial would false-fail a
// perfectly good cert. The executor dials with InsecureSkipVerify, completes
// the handshake, then inspects the leaf certificate manually.
//
// Up/down semantics (v1):
//   - down if the TLS handshake cannot complete at all
//   - down if the leaf certificate is already expired (NotAfter in the past)
//   - up otherwise
//
// Chain-invalid / hostname-mismatch are deliberately NOT hard failures in v1.
//
// Whenever a leaf cert is read (valid OR expired) the executor reports
// days-to-expiry on the Result so the heartbeat can roll it up. The pre-expiry
// *warning* threshold is owned by the backend — the agent applies none.
type SSLCheck struct{}

// SSLParams carries the few fields the SSL check needs. CheckDef.SkipTLSVerify
// is intentionally absent: the SSL type always insecure-dials-then-inspects.
type SSLParams struct {
	Host    string
	Port    int
	Timeout time.Duration
}

// Run dials the target over TLS (insecure), inspects the leaf certificate,
// and returns the up/down outcome plus days-to-expiry. Honors ctx + timeout.
func (SSLCheck) Run(ctx context.Context, p SSLParams) Result {
	addr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	start := time.Now()

	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: p.Timeout},
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // by design — internal CA certs, manual leaf inspection below
			ServerName:         p.Host,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Result{
			Up:             false,
			ResponseTimeMs: msSince(start),
			ErrorMessage:   fmt.Sprintf("tls dial %s: %s", addr, err.Error()),
		}
	}
	defer func() { _ = conn.Close() }()
	rtt := msSince(start)

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return Result{
			Up:             false,
			ResponseTimeMs: rtt,
			ErrorMessage:   fmt.Sprintf("tls dial %s: unexpected connection type", addr),
		}
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return Result{
			Up:             false,
			ResponseTimeMs: rtt,
			ErrorMessage:   fmt.Sprintf("tls %s: handshake completed but no peer certificate presented", addr),
		}
	}

	leaf := certs[0]
	days := daysToExpiry(leaf.NotAfter, time.Now())
	if leaf.NotAfter.Before(time.Now()) {
		return Result{
			Up:               false,
			ResponseTimeMs:   rtt,
			ErrorMessage:     fmt.Sprintf("certificate expired %d days ago", -days),
			CertDaysToExpiry: &days,
		}
	}
	return Result{
		Up:               true,
		ResponseTimeMs:   rtt,
		CertDaysToExpiry: &days,
	}
}

// daysToExpiry computes floor((notAfter - now) / 24h). Negative for an
// already-expired cert, possibly 0 for a cert expiring within the day.
//
// Integer division truncates toward zero, which is wrong for negative
// durations (an expired cert), so compute the floor explicitly.
func daysToExpiry(notAfter, now time.Time) int {
	const day = 24 * time.Hour
	remaining := notAfter.Sub(now)
	days := remaining / day
	if remaining < 0 && remaining%day != 0 {
		days--
	}
	return int(days)
}
