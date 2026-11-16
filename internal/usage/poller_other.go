//go:build !linux

package usage

import (
	"context"

	"github.com/statusharbor/lighthouse/internal/ebpf/identity"
	"github.com/statusharbor/lighthouse/internal/transport"
)

// Poller is Linux only; elsewhere it reports nothing.
type Poller struct{ Acct *Accountant }

func NewPoller(acct *Accountant, _ string, _ func(context.Context, string) (string, string, bool)) *Poller {
	return &Poller{Acct: acct}
}

func (*Poller) GroupOf(context.Context, identity.Key, string) string { return "" }

func (*Poller) Collect() ([]transport.HostSample, error) { return nil, nil }
