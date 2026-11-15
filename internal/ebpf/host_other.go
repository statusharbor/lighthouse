//go:build !linux

package ebpf

// ProbeHost returns an empty Host off Linux; the agent never starts the
// Manager there.
func ProbeHost() Host { return Host{} }
