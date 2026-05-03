package checks

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// UDPCheck is a connection-less probe — UDP has no handshake so a "successful
// dial" doesn't actually mean anything. The agent sends a payload and treats
// the check as up only if a response arrives within the timeout (and
// optionally contains the expected substring).
//
// Without a payload + expected response, UDP checks are inherently unreliable
// — we still allow them as a "did it accept the packet" signal but flag the
// limitation in the executor's error message.
type UDPCheck struct{}

// UDPParams mirrors TCPParams; SendPayload is effectively required for a
// meaningful result (see executor docstring).
type UDPParams struct {
	Host           string
	Port           int
	Timeout        time.Duration
	SendPayload    string
	ExpectContains string
}

func (UDPCheck) Run(ctx context.Context, p UDPParams) Result {
	addr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	d := net.Dialer{Timeout: p.Timeout}
	start := time.Now()

	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return Result{
			Up:             false,
			ResponseTimeMs: msSince(start),
			ErrorMessage:   fmt.Sprintf("dial udp %s: %s", addr, err.Error()),
		}
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.Timeout))

	payload := p.SendPayload
	if payload == "" {
		// No payload means we can't observe anything — UDP send to a closed
		// port often goes through silently. We still send a single byte so
		// at least an ICMP unreachable can come back.
		payload = "\x00"
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		return Result{
			Up:             false,
			ResponseTimeMs: msSince(start),
			ErrorMessage:   fmt.Sprintf("write udp %s: %s", addr, err.Error()),
		}
	}

	if p.ExpectContains == "" {
		// No response assertion — we declare up if the write didn't fail
		// AND no ICMP unreachable came back during the timeout window.
		// Read with a short deadline; an error means either no response
		// (treated as Up — UDP semantics) OR an ICMP error (treated as Down).
		buf := make([]byte, 1500)
		_, readErr := conn.Read(buf)
		rtt := msSince(start)
		if readErr != nil && isUDPNoResponse(readErr) {
			return Result{Up: true, ResponseTimeMs: rtt}
		}
		if readErr != nil {
			return Result{
				Up:             false,
				ResponseTimeMs: rtt,
				ErrorMessage:   fmt.Sprintf("udp read: %s", readErr.Error()),
			}
		}
		return Result{Up: true, ResponseTimeMs: rtt}
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	rtt := msSince(start)
	if err != nil {
		return Result{
			Up:             false,
			ResponseTimeMs: rtt,
			ErrorMessage:   fmt.Sprintf("udp read %s: %s", addr, err.Error()),
		}
	}
	if !strings.Contains(string(buf[:n]), p.ExpectContains) {
		return Result{
			Up:             false,
			ResponseTimeMs: rtt,
			ErrorMessage:   fmt.Sprintf("expected substring not in udp response (read %d bytes)", n),
		}
	}
	return Result{Up: true, ResponseTimeMs: rtt}
}

// isUDPNoResponse: a timeout reading from UDP is the "happy path" when no
// response is expected — distinguishes from "ICMP unreachable" which surfaces
// as a connection-refused error.
func isUDPNoResponse(err error) bool {
	if err == nil {
		return true
	}
	var ne net.Error
	if asNetErr(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

func asNetErr(err error, target *net.Error) bool {
	for err != nil {
		if ne, ok := err.(net.Error); ok {
			*target = ne
			return true
		}
		type unwrapper interface{ Unwrap() error }
		uw, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = uw.Unwrap()
	}
	return false
}
