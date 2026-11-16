//go:build !linux

package agent

import (
	"context"

	"github.com/statusharbor/lighthouse/internal/ebpf"
	"github.com/statusharbor/lighthouse/internal/traces"
	"github.com/statusharbor/lighthouse/internal/transport"
)

// NewEBPF returns nils off Linux: no eBPF collectors exist there.
func NewEBPF(context.Context, *Config, bool, func(context.Context, []transport.EBPFEnvelope) error, string, func() []CheckDefinition, *traces.Pipeline) (*ebpf.Manager, Collector, *ebpf.Batcher) {
	return nil, nil, nil
}
