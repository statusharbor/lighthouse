package ebpftest

import "github.com/cilium/ebpf/rlimit"

// Kernels before 5.11 charge BPF memory against RLIMIT_MEMLOCK. Without
// the privilege to raise it the tests skip on their own capability check.
func init() { _ = rlimit.RemoveMemlock() }
