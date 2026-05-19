package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/statusharbor/lighthouse/internal/agent"
)

// These tests cover realExecutor.Run's dispatch: that each check type routes
// to the right protocol check and produces a sensible observation. The
// per-protocol check logic itself is unit-tested in internal/checks — here we
// only assert the switch wires each `case` to its check.

func TestRealExecutor_HTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	obs := newRealExecutor().Run(context.Background(), agent.CheckDefinition{
		ID: "h", Type: "http", URL: srv.URL, Method: "GET",
		ExpectedStatusCode: 200, TimeoutSeconds: 5,
	})
	if obs.State != agent.StateUp {
		t.Errorf("http: State = %q, want up (%s)", obs.State, obs.ErrorMessage)
	}
}

func TestRealExecutor_HTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	obs := newRealExecutor().Run(context.Background(), agent.CheckDefinition{
		ID: "hs", Type: "https", URL: srv.URL, Method: "GET",
		ExpectedStatusCode: 200, SkipTLSVerify: true, TimeoutSeconds: 5,
	})
	if obs.State != agent.StateUp {
		t.Errorf("https: State = %q, want up (%s)", obs.State, obs.ErrorMessage)
	}
}

func TestRealExecutor_TCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	obs := newRealExecutor().Run(context.Background(), agent.CheckDefinition{
		ID: "t", Type: "tcp", URL: ln.Addr().String(), TimeoutSeconds: 5,
	})
	if obs.State != agent.StateUp {
		t.Errorf("tcp: State = %q, want up (%s)", obs.State, obs.ErrorMessage)
	}
}

func TestRealExecutor_UDP(t *testing.T) {
	// A UDP listener that silently absorbs datagrams. Per the UDP check's
	// semantics (no expected response configured), a reachable port that
	// doesn't reply counts as up.
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := conn.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	obs := newRealExecutor().Run(context.Background(), agent.CheckDefinition{
		ID: "u", Type: "udp", URL: fmt.Sprintf("127.0.0.1:%d", port), TimeoutSeconds: 1,
	})
	if obs.State != agent.StateUp {
		t.Errorf("udp: State = %q, want up (%s)", obs.State, obs.ErrorMessage)
	}
}

func TestRealExecutor_SSL(t *testing.T) {
	// httptest's TLS server presents a long-lived test certificate; the SSL
	// check insecure-dials and inspects it — not expired → up.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	obs := newRealExecutor().Run(context.Background(), agent.CheckDefinition{
		ID: "s", Type: "ssl", URL: srv.URL, TimeoutSeconds: 5,
	})
	if obs.State != agent.StateUp {
		t.Errorf("ssl: State = %q, want up (%s)", obs.State, obs.ErrorMessage)
	}
}

func TestRealExecutor_DNS(t *testing.T) {
	// localhost resolves to loopback deterministically (Go special-cases it),
	// so this exercises the dns dispatch without external network.
	obs := newRealExecutor().Run(context.Background(), agent.CheckDefinition{
		ID: "d", Type: "dns", URL: "localhost",
		DNSRecordType: "A", DNSExpectedIPs: []string{"127.0.0.1"}, TimeoutSeconds: 5,
	})
	if obs.State != agent.StateUp {
		t.Errorf("dns: State = %q, want up (%s)", obs.State, obs.ErrorMessage)
	}
}

func TestRealExecutor_UnknownType(t *testing.T) {
	obs := newRealExecutor().Run(context.Background(), agent.CheckDefinition{
		ID: "x", Type: "bogus", TimeoutSeconds: 5,
	})
	if obs.State != agent.StateDown {
		t.Errorf("unknown type: State = %q, want down", obs.State)
	}
	if !strings.Contains(obs.ErrorMessage, "unknown check type") {
		t.Errorf("unknown type: ErrorMessage = %q, want it to mention 'unknown check type'", obs.ErrorMessage)
	}
}
