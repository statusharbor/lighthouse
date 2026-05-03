package checks

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// startTCPListener spins up a goroutine that accepts one connection,
// reads at most maxRead bytes, and writes resp before closing. Returns
// the listener address (host:port).
func startTCPListener(t *testing.T, resp string, maxRead int) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				if maxRead > 0 {
					buf := make([]byte, maxRead)
					_, _ = c.Read(buf)
				}
				if resp != "" {
					_, _ = c.Write([]byte(resp))
				}
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestTCP_DialSucceeds(t *testing.T) {
	host, port := startTCPListener(t, "", 0)
	got := TCPCheck{}.Run(context.Background(), TCPParams{
		Host:    host,
		Port:    port,
		Timeout: 2 * time.Second,
	})
	if !got.Up {
		t.Errorf("expected Up=true, got Down: %s", got.ErrorMessage)
	}
}

func TestTCP_DialRefusedReturnsDown(t *testing.T) {
	// Port 1 is reserved/never-listening; will fail.
	got := TCPCheck{}.Run(context.Background(), TCPParams{
		Host:    "127.0.0.1",
		Port:    1,
		Timeout: 500 * time.Millisecond,
	})
	if got.Up {
		t.Errorf("expected Down, got Up")
	}
	if got.ErrorMessage == "" {
		t.Error("expected error message")
	}
}

func TestTCP_PayloadAndExpectResponse(t *testing.T) {
	host, port := startTCPListener(t, "PONG", 64)
	got := TCPCheck{}.Run(context.Background(), TCPParams{
		Host:           host,
		Port:           port,
		Timeout:        2 * time.Second,
		SendPayload:    "PING",
		ExpectContains: "PONG",
	})
	if !got.Up {
		t.Errorf("expected Up, got Down: %s", got.ErrorMessage)
	}
}

func TestTCP_ExpectMissingReturnsDown(t *testing.T) {
	host, port := startTCPListener(t, "BANANA", 64)
	got := TCPCheck{}.Run(context.Background(), TCPParams{
		Host:           host,
		Port:           port,
		Timeout:        2 * time.Second,
		SendPayload:    "PING",
		ExpectContains: "PONG",
	})
	if got.Up {
		t.Error("expected Down when response doesn't contain expected substring")
	}
}

func TestParseTCPTarget(t *testing.T) {
	cases := []struct {
		in           string
		fallbackPort int
		wantHost     string
		wantPort     int
		wantErr      bool
	}{
		{"example.com:5432", 0, "example.com", 5432, false},
		{"tcp://example.com:5432", 0, "example.com", 5432, false},
		{"example.com", 5432, "example.com", 5432, false},
		{"", 5432, "", 0, true},
		{"example.com", 0, "example.com", 0, true}, // port required somewhere
	}
	for _, c := range cases {
		t.Run(c.in+":"+strconv.Itoa(c.fallbackPort), func(t *testing.T) {
			host, port, err := ParseTCPTarget(c.in, c.fallbackPort)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, c.wantErr)
			}
			if c.wantErr {
				return
			}
			if host != c.wantHost || port != c.wantPort {
				t.Errorf("got (%q, %d), want (%q, %d)", host, port, c.wantHost, c.wantPort)
			}
		})
	}
}
