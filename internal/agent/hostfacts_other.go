//go:build !linux

package agent

import "github.com/statusharbor/lighthouse/internal/transport"

// collectHostFacts returns nil off Linux: the survey only matters for
// hosts that could run the eBPF collectors.
func collectHostFacts() *transport.HostFacts { return nil }
