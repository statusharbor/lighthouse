package checks

import (
	"context"
	"net"
	"testing"
	"time"
)

// startUDPEcho responds with `resp` to every datagram. Returns the listener
// address.
func startUDPEcho(t *testing.T, resp string) (host string, port int) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_ = n
			if resp != "" {
				_, _ = conn.WriteToUDP([]byte(resp), peer)
			}
		}
	}()

	la := conn.LocalAddr().(*net.UDPAddr)
	return "127.0.0.1", la.Port
}

func TestUDP_PayloadAndExpectResponse(t *testing.T) {
	host, port := startUDPEcho(t, "PONG")
	got := UDPCheck{}.Run(context.Background(), UDPParams{
		Host:           host,
		Port:           port,
		Timeout:        500 * time.Millisecond,
		SendPayload:    "PING",
		ExpectContains: "PONG",
	})
	if !got.Up {
		t.Errorf("expected Up, got Down: %s", got.ErrorMessage)
	}
}

func TestUDP_ExpectMismatchReturnsDown(t *testing.T) {
	host, port := startUDPEcho(t, "BANANA")
	got := UDPCheck{}.Run(context.Background(), UDPParams{
		Host:           host,
		Port:           port,
		Timeout:        500 * time.Millisecond,
		SendPayload:    "PING",
		ExpectContains: "PONG",
	})
	if got.Up {
		t.Error("expected Down when response doesn't contain expected substring")
	}
}

func TestUDP_SilentReceiver_NoExpect_CountsAsUp(t *testing.T) {
	// A listener that accepts datagrams but never replies. From the
	// agent's perspective this is the most common "is the port open"
	// scenario for UDP — the read times out, which the executor treats
	// as Up when no expected response is configured.
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	ln, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := ln.ReadFromUDP(buf); err != nil {
				return
			}
			// Silently absorb — no response.
		}
	}()
	la := ln.LocalAddr().(*net.UDPAddr)

	got := UDPCheck{}.Run(context.Background(), UDPParams{
		Host:    "127.0.0.1",
		Port:    la.Port,
		Timeout: 200 * time.Millisecond,
	})
	if !got.Up {
		t.Errorf("silent receiver should count as Up when no expect set, got Down: %s", got.ErrorMessage)
	}
}

func TestUDP_ICMPUnreachable_ReturnsDown(t *testing.T) {
	// On localhost, a closed UDP port returns ICMP unreachable, which the
	// kernel surfaces as "connection refused" on the subsequent read.
	// That's a real signal the port is closed — executor must report Down.
	conn, _ := net.ListenPacket("udp", "127.0.0.1:0")
	port := conn.LocalAddr().(*net.UDPAddr).Port
	_ = conn.Close()

	got := UDPCheck{}.Run(context.Background(), UDPParams{
		Host:    "127.0.0.1",
		Port:    port,
		Timeout: 200 * time.Millisecond,
	})
	if got.Up {
		t.Error("ICMP unreachable means the port is genuinely closed; executor must report Down")
	}
}
