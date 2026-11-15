package checks

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func traceServer(t *testing.T, got *string) *httptest.Server {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = r.Header.Get("traceparent")
		time.Sleep(5 * time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func phaseNames(tr *Trace) []string {
	var names []string
	for _, p := range tr.Phases {
		names = append(names, p.Name)
	}
	return names
}

// TRC-U-P1 and TRC-U-P2: phases cover the run and the header carries the
// span's trace.
func TestHTTPCheck_TraceParentAndPhases(t *testing.T) {
	var header string
	srv := traceServer(t, &header)
	tr := NewTrace(true)
	start := time.Now()
	res := HTTPCheck{}.Run(context.Background(), HTTPParams{URL: srv.URL, Timeout: 5 * time.Second, SkipTLSVerify: true, Trace: tr})
	total := time.Since(start)
	if !res.Up {
		t.Fatalf("check down: %s", res.ErrorMessage)
	}
	parts := strings.Split(header, "-")
	if len(parts) != 4 || parts[0] != "00" || parts[1] != hex.EncodeToString(tr.TraceID[:]) || parts[2] != hex.EncodeToString(tr.SpanID[:]) || parts[3] != "01" {
		t.Fatalf("traceparent = %q", header)
	}
	names := strings.Join(phaseNames(tr), ",")
	if names != "connect,tls,request,response" {
		t.Fatalf("phases = %s", names) // an IP target has no dns phase
	}
	var sum time.Duration
	for _, p := range tr.Phases {
		sum += p.End.Sub(p.Start)
	}
	if gap := total - sum; gap < 0 || gap > 10*time.Millisecond {
		t.Fatalf("phases add up to %v of %v", sum, total)
	}
}

// TRC-U-F4: the header can be turned off; the phases are still recorded.
func TestHTTPCheck_TraceWithoutHeader(t *testing.T) {
	var header string
	srv := traceServer(t, &header)
	tr := NewTrace(false)
	HTTPCheck{}.Run(context.Background(), HTTPParams{URL: srv.URL, Timeout: 5 * time.Second, SkipTLSVerify: true, Trace: tr})
	if header != "" {
		t.Fatalf("traceparent sent: %q", header)
	}
	if len(tr.Phases) == 0 {
		t.Fatal("no phases")
	}
}
