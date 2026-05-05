package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/statusharbor/lighthouse/internal/agent"
	"github.com/statusharbor/lighthouse/internal/checks"
)

// realExecutor dispatches to the appropriate protocol-level check based on
// CheckDefinition.Type. Lives in cmd/lighthouse rather than internal/agent
// to keep the agent package free of internal/checks dependencies (the
// executor is the seam between the two).
type realExecutor struct{}

func newRealExecutor() *realExecutor { return &realExecutor{} }

func (e *realExecutor) Run(ctx context.Context, def agent.CheckDefinition) agent.CheckObservation {
	timeout := time.Duration(def.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	switch strings.ToLower(def.Type) {
	case "http", "https":
		var rh []checks.HeaderPair
		for _, h := range def.RequestHeaders {
			rh = append(rh, checks.HeaderPair{Key: h.Key, Value: h.Value})
		}
		var eh []checks.ExpectedHeader
		for _, h := range def.ExpectedHeaders {
			eh = append(eh, checks.ExpectedHeader{Key: h.Key, Value: h.Value, Match: h.Match})
		}
		return toObservation(checks.HTTPCheck{}.Run(ctx, checks.HTTPParams{
			URL:                def.URL,
			Method:             def.Method,
			Timeout:            timeout,
			ExpectedStatusCode: def.ExpectedStatusCode,
			KeywordCheck:       def.KeywordCheck,
			KeywordPresent:     def.KeywordPresent,
			SkipTLSVerify:      def.SkipTLSVerify,
			RequestHeaders:     rh,
			RequestBody:        def.RequestBody,
			ExpectedHeaders:    eh,
		}))
	case "tcp":
		host, port, err := checks.ParseTCPTarget(def.URL, 0)
		if err != nil {
			return downObservation(fmt.Sprintf("invalid tcp target: %s", err.Error()))
		}
		return toObservation(checks.TCPCheck{}.Run(ctx, checks.TCPParams{
			Host:    host,
			Port:    port,
			Timeout: timeout,
		}))
	case "udp":
		host, port, err := checks.ParseTCPTarget(def.URL, 0) // same target syntax
		if err != nil {
			return downObservation(fmt.Sprintf("invalid udp target: %s", err.Error()))
		}
		return toObservation(checks.UDPCheck{}.Run(ctx, checks.UDPParams{
			Host:    host,
			Port:    port,
			Timeout: timeout,
		}))
	default:
		slog.Warn("unknown check type — reporting down",
			"check_id", def.ID, "type", def.Type)
		return downObservation(fmt.Sprintf("unknown check type %q", def.Type))
	}
}

func toObservation(r checks.Result) agent.CheckObservation {
	state := agent.StateUp
	if !r.Up {
		state = agent.StateDown
	}
	return agent.CheckObservation{
		State:          state,
		ResponseTimeMs: r.ResponseTimeMs,
		StatusCode:     r.StatusCode,
		ErrorMessage:   r.ErrorMessage,
		ObservedAt:     time.Now().UTC(),
	}
}

func downObservation(msg string) agent.CheckObservation {
	return agent.CheckObservation{
		State:        agent.StateDown,
		ErrorMessage: msg,
		ObservedAt:   time.Now().UTC(),
	}
}
