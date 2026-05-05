package checks

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func startHTTPServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// capturingServer records the inbound request (headers + body) so tests can
// assert the agent forwarded request_headers / request_body correctly.
// Optional respHeaders are written on the response before the status.
type capturedRequest struct {
	mu      sync.Mutex
	headers http.Header
	body    string
}

func (c *capturedRequest) Headers() http.Header {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(http.Header, len(c.headers))
	for k, v := range c.headers {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func (c *capturedRequest) Body() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.body
}

func startCapturingHTTPServer(t *testing.T, status int, respHeaders map[string]string, body string) (*httptest.Server, *capturedRequest) {
	t.Helper()
	cap := &capturedRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		cap.mu.Lock()
		cap.headers = r.Header.Clone()
		cap.body = string(b)
		cap.mu.Unlock()

		for k, v := range respHeaders {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

func TestHTTP_200_WithExpectedKeyword_Up(t *testing.T) {
	srv := startHTTPServer(t, 200, "ok\nstatus: HEALTHY\n")
	got := HTTPCheck{}.Run(context.Background(), HTTPParams{
		URL:                srv.URL,
		Timeout:            2 * time.Second,
		ExpectedStatusCode: 200,
		KeywordCheck:       "HEALTHY",
		KeywordPresent:     true,
	})
	if !got.Up {
		t.Errorf("expected Up, got Down: %s", got.ErrorMessage)
	}
	if got.StatusCode != 200 {
		t.Errorf("StatusCode = %d", got.StatusCode)
	}
}

func TestHTTP_StatusMismatch_Down(t *testing.T) {
	srv := startHTTPServer(t, 500, "boom")
	got := HTTPCheck{}.Run(context.Background(), HTTPParams{
		URL:                srv.URL,
		Timeout:            2 * time.Second,
		ExpectedStatusCode: 200,
	})
	if got.Up {
		t.Error("expected Down on status mismatch")
	}
	if got.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500 (raw status surfaced even when down)", got.StatusCode)
	}
}

func TestHTTP_KeywordMissingWhenPresentExpected_Down(t *testing.T) {
	srv := startHTTPServer(t, 200, "service is alive")
	got := HTTPCheck{}.Run(context.Background(), HTTPParams{
		URL:                srv.URL,
		Timeout:            2 * time.Second,
		ExpectedStatusCode: 200,
		KeywordCheck:       "MAINTENANCE",
		KeywordPresent:     true,
	})
	if got.Up {
		t.Error("expected Down when keyword missing")
	}
}

func TestHTTP_KeywordPresentWhenAbsenceExpected_Down(t *testing.T) {
	srv := startHTTPServer(t, 200, "service in MAINTENANCE mode")
	got := HTTPCheck{}.Run(context.Background(), HTTPParams{
		URL:                srv.URL,
		Timeout:            2 * time.Second,
		ExpectedStatusCode: 200,
		KeywordCheck:       "MAINTENANCE",
		KeywordPresent:     false, // expect "MAINTENANCE" to NOT be present
	})
	if got.Up {
		t.Error("expected Down when keyword present but absence expected")
	}
}

func TestHTTP_DefaultsAreApplied(t *testing.T) {
	srv := startHTTPServer(t, 200, "")
	// Empty Method + ExpectedStatusCode → defaults to GET, 200.
	got := HTTPCheck{}.Run(context.Background(), HTTPParams{
		URL:     srv.URL,
		Timeout: 2 * time.Second,
	})
	if !got.Up {
		t.Errorf("expected Up: %s", got.ErrorMessage)
	}
}

func TestHTTP_NetworkErrorIsDown(t *testing.T) {
	got := HTTPCheck{}.Run(context.Background(), HTTPParams{
		URL:                "http://127.0.0.1:1",
		Timeout:            500 * time.Millisecond,
		ExpectedStatusCode: 200,
	})
	if got.Up {
		t.Error("expected Down on connection refused")
	}
	if got.ErrorMessage == "" {
		t.Error("expected error message")
	}
}

func TestHTTP_TimeoutIsDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_, _ = w.Write([]byte("late"))
	}))
	defer srv.Close()

	got := HTTPCheck{}.Run(context.Background(), HTTPParams{
		URL:                srv.URL,
		Timeout:            100 * time.Millisecond,
		ExpectedStatusCode: 200,
	})
	if got.Up {
		t.Error("expected Down on timeout")
	}
}

// RequestHeaders / RequestBody must reach the upstream service.
func TestHTTP_RequestHeadersForwarded(t *testing.T) {
	srv, cap := startCapturingHTTPServer(t, 200, nil, "")
	got := HTTPCheck{}.Run(context.Background(), HTTPParams{
		URL:                srv.URL,
		Timeout:            2 * time.Second,
		ExpectedStatusCode: 200,
		RequestHeaders: []HeaderPair{
			{Key: "X-Auth", Value: "secret-token"},
			{Key: "X-Trace", Value: "abc-123"},
		},
	})
	if !got.Up {
		t.Fatalf("expected Up: %s", got.ErrorMessage)
	}
	headers := cap.Headers()
	if got := headers.Get("X-Auth"); got != "secret-token" {
		t.Errorf("X-Auth = %q, want secret-token", got)
	}
	if got := headers.Get("X-Trace"); got != "abc-123" {
		t.Errorf("X-Trace = %q, want abc-123", got)
	}
}

func TestHTTP_RequestBodyForwarded(t *testing.T) {
	srv, cap := startCapturingHTTPServer(t, 200, nil, "")
	body := `{"ping":"hi"}`
	got := HTTPCheck{}.Run(context.Background(), HTTPParams{
		URL:                srv.URL,
		Method:             "POST",
		Timeout:            2 * time.Second,
		ExpectedStatusCode: 200,
		RequestBody:        body,
	})
	if !got.Up {
		t.Fatalf("expected Up: %s", got.ErrorMessage)
	}
	if cap.Body() != body {
		t.Errorf("server saw body %q, want %q", cap.Body(), body)
	}
}

// Expected response headers — three match modes, each in pass + fail variant.
func TestHTTP_ExpectedHeader_PresentMatch(t *testing.T) {
	// Pass: header is set.
	srv, _ := startCapturingHTTPServer(t, 200, map[string]string{"X-Powered-By": "test"}, "")
	got := HTTPCheck{}.Run(context.Background(), HTTPParams{
		URL:                srv.URL,
		Timeout:            2 * time.Second,
		ExpectedStatusCode: 200,
		ExpectedHeaders:    []ExpectedHeader{{Key: "X-Powered-By", Match: "present"}},
	})
	if !got.Up {
		t.Errorf("expected Up when header present: %s", got.ErrorMessage)
	}

	// Fail: header missing.
	srv2, _ := startCapturingHTTPServer(t, 200, nil, "")
	got = HTTPCheck{}.Run(context.Background(), HTTPParams{
		URL:                srv2.URL,
		Timeout:            2 * time.Second,
		ExpectedStatusCode: 200,
		ExpectedHeaders:    []ExpectedHeader{{Key: "X-Powered-By", Match: "present"}},
	})
	if got.Up {
		t.Error("expected Down when header missing")
	}
}

func TestHTTP_ExpectedHeader_ExactMatch(t *testing.T) {
	srv, _ := startCapturingHTTPServer(t, 200, map[string]string{"Content-Type": "application/json"}, "")
	got := HTTPCheck{}.Run(context.Background(), HTTPParams{
		URL:                srv.URL,
		Timeout:            2 * time.Second,
		ExpectedStatusCode: 200,
		ExpectedHeaders:    []ExpectedHeader{{Key: "Content-Type", Value: "application/json", Match: "exact"}},
	})
	if !got.Up {
		t.Errorf("expected Up on exact match: %s", got.ErrorMessage)
	}

	// Fail: server sends a charset-suffixed variant; exact match rejects.
	srv2, _ := startCapturingHTTPServer(t, 200, map[string]string{"Content-Type": "application/json; charset=utf-8"}, "")
	got = HTTPCheck{}.Run(context.Background(), HTTPParams{
		URL:                srv2.URL,
		Timeout:            2 * time.Second,
		ExpectedStatusCode: 200,
		ExpectedHeaders:    []ExpectedHeader{{Key: "Content-Type", Value: "application/json", Match: "exact"}},
	})
	if got.Up {
		t.Error("expected Down on exact mismatch")
	}
}

func TestHTTP_ExpectedHeader_ContainsMatch(t *testing.T) {
	// Pass: substring is present.
	srv, _ := startCapturingHTTPServer(t, 200, map[string]string{"Content-Type": "application/json; charset=utf-8"}, "")
	got := HTTPCheck{}.Run(context.Background(), HTTPParams{
		URL:                srv.URL,
		Timeout:            2 * time.Second,
		ExpectedStatusCode: 200,
		ExpectedHeaders:    []ExpectedHeader{{Key: "Content-Type", Value: "application/json", Match: "contains"}},
	})
	if !got.Up {
		t.Errorf("expected Up on contains match: %s", got.ErrorMessage)
	}

	// Fail: substring not present.
	srv2, _ := startCapturingHTTPServer(t, 200, map[string]string{"Content-Type": "text/html"}, "")
	got = HTTPCheck{}.Run(context.Background(), HTTPParams{
		URL:                srv2.URL,
		Timeout:            2 * time.Second,
		ExpectedStatusCode: 200,
		ExpectedHeaders:    []ExpectedHeader{{Key: "Content-Type", Value: "application/json", Match: "contains"}},
	})
	if got.Up {
		t.Error("expected Down on contains mismatch")
	}
}

// SkipTLSVerify exists in HTTPParams already but had no test. Asserts both
// directions against a self-signed httptest.NewTLSServer.
func TestHTTP_SkipTLSVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)

	// SkipTLSVerify=true → comes Up despite self-signed cert.
	got := HTTPCheck{}.Run(context.Background(), HTTPParams{
		URL:                srv.URL,
		Timeout:            2 * time.Second,
		ExpectedStatusCode: 200,
		SkipTLSVerify:      true,
	})
	if !got.Up {
		t.Errorf("expected Up with SkipTLSVerify=true: %s", got.ErrorMessage)
	}

	// SkipTLSVerify=false → cert verification fails → Down.
	got = HTTPCheck{}.Run(context.Background(), HTTPParams{
		URL:                srv.URL,
		Timeout:            2 * time.Second,
		ExpectedStatusCode: 200,
		SkipTLSVerify:      false,
	})
	if got.Up {
		t.Error("expected Down with SkipTLSVerify=false against self-signed cert")
	}
}
