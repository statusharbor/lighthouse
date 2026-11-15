// Package ebpftest prepares a test process for loading BPF programs the
// way the agent prepares itself at startup (internal/agent/ebpf_linux.go).
// Kernel tests import it for its side effect:
//
//	import _ "github.com/statusharbor/lighthouse/internal/ebpf/ebpftest"
package ebpftest
