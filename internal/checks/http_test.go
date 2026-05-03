package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
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
