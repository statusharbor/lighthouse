package main

import (
	"context"
	"time"

	"github.com/statusharbor/lighthouse/internal/agent"
)

// realExecutor is the production CheckExecutor. The actual http/https/tcp/udp
// implementations live in internal/checks (sanitized copies of the main
// repo's executors); for now this is a placeholder that always reports "up"
// so the agent runs end-to-end against a real Console without check_id
// errors.
//
// Replace this with a dispatch-by-type implementation once internal/checks
// lands.
type realExecutor struct{}

func newRealExecutor() *realExecutor { return &realExecutor{} }

func (r *realExecutor) Run(ctx context.Context, def agent.CheckDefinition) agent.CheckObservation {
	_ = ctx
	_ = def
	return agent.CheckObservation{
		State:      agent.StateUp,
		ObservedAt: time.Now().UTC(),
	}
}
