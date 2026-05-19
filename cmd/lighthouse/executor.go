package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
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
		timeout = 5 * time.Second
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
	case "ssl":
		host, port, err := checks.ParseTCPTarget(def.URL, 443) // default TLS port
		if err != nil {
			return downObservation(fmt.Sprintf("invalid ssl target: %s", err.Error()))
		}
		return toObservation(checks.SSLCheck{}.Run(ctx, checks.SSLParams{
			Host:    host,
			Port:    port,
			Timeout: timeout,
		}))
	case "dns":
		host := dnsHost(def.URL)
		if host == "" {
			return downObservation("invalid dns target: empty host")
		}
		return toObservation(checks.DNSCheck{}.Run(ctx, checks.DNSParams{
			Host:           host,
			RecordType:     def.DNSRecordType,
			ExpectedValues: def.DNSExpectedIPs,
			ResolverAddr:   def.DNSResolver,
			Timeout:        timeout,
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
		State:            state,
		ResponseTimeMs:   r.ResponseTimeMs,
		StatusCode:       r.StatusCode,
		ErrorMessage:     r.ErrorMessage,
		ObservedAt:       time.Now().UTC(),
		CertDaysToExpiry: r.CertDaysToExpiry,
	}
}

// dnsHost extracts the record name to resolve from a DNS check's URL field.
// The field normally carries a bare hostname ("api.internal") but tolerates a
// scheme prefix, an explicit port and a trailing path so a host accidentally
// configured as a full URL still resolves cleanly.
func dnsHost(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	// Strip any trailing path/query and an optional :port.
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return s
}

func downObservation(msg string) agent.CheckObservation {
	return agent.CheckObservation{
		State:        agent.StateDown,
		ErrorMessage: msg,
		ObservedAt:   time.Now().UTC(),
	}
}
