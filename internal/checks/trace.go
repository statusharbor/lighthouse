package checks

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"net/http/httptrace"
	"sync"
	"time"
)

// Trace records one check run as a span with phase children
// (status-harbor docs/eBPF/11-traces.md, "Check spans"). Executors fill
// Phases; the caller turns it into OTLP spans.
type Trace struct {
	TraceID [16]byte
	SpanID  [8]byte
	// SendHeader adds a W3C traceparent to HTTP checks, so OBI on the
	// target continues the trace under this span.
	SendHeader bool

	mu     sync.Mutex
	Phases []Phase
}

// Phase is one child span: dns, connect, tls, request (to first byte) or
// response (body read).
type Phase struct {
	Name       string
	Start, End time.Time
}

// NewTrace makes random IDs.
func NewTrace(sendHeader bool) *Trace {
	t := &Trace{SendHeader: sendHeader}
	_, _ = rand.Read(t.TraceID[:])
	_, _ = rand.Read(t.SpanID[:])
	return t
}

// Traceparent is the W3C header value, sampled.
func (t *Trace) Traceparent() string {
	return "00-" + hex.EncodeToString(t.TraceID[:]) + "-" + hex.EncodeToString(t.SpanID[:]) + "-01"
}

func (t *Trace) add(name string, start, end time.Time) {
	if t == nil || start.IsZero() || end.Before(start) {
		return
	}
	t.mu.Lock()
	t.Phases = append(t.Phases, Phase{Name: name, Start: start, End: end})
	t.mu.Unlock()
}

// phaseClock collects httptrace timestamps. Reused connections have no
// dns, connect or tls phase.
type phaseClock struct {
	mu                                                        sync.Mutex
	dnsStart, dnsDone, connStart, connDone, tlsStart, tlsDone time.Time
	wrote, firstByte                                          time.Time
}

func (c *phaseClock) set(dst *time.Time) {
	c.mu.Lock()
	if dst.IsZero() {
		*dst = time.Now()
	}
	c.mu.Unlock()
}

func (c *phaseClock) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart:             func(httptrace.DNSStartInfo) { c.set(&c.dnsStart) },
		DNSDone:              func(httptrace.DNSDoneInfo) { c.set(&c.dnsDone) },
		ConnectStart:         func(string, string) { c.set(&c.connStart) },
		ConnectDone:          func(string, string, error) { c.set(&c.connDone) },
		TLSHandshakeStart:    func() { c.set(&c.tlsStart) },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { c.set(&c.tlsDone) },
		WroteRequest:         func(httptrace.WroteRequestInfo) { c.set(&c.wrote) },
		GotFirstResponseByte: func() { c.set(&c.firstByte) },
	}
}

// record turns the clock into phases; end is when the body was read.
func (c *phaseClock) record(t *Trace, start, end time.Time) {
	if t == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t.add("dns", c.dnsStart, c.dnsDone)
	t.add("connect", c.connStart, c.connDone)
	t.add("tls", c.tlsStart, c.tlsDone)
	// request: from the request leaving (after any handshake) to the
	// first response byte.
	reqStart := start
	for _, ts := range []time.Time{c.dnsDone, c.connDone, c.tlsDone} {
		if ts.After(reqStart) {
			reqStart = ts
		}
	}
	if !c.firstByte.IsZero() {
		t.add("request", reqStart, c.firstByte)
		t.add("response", c.firstByte, end)
	}
}
