// Package overhead measures what the eBPF collectors cost a busy host
// (docs/eBPF/01-foundation.md, "Self-metrics and benchmark"): the same
// reference load runs with the collectors off and on, and the difference
// in CPU time is the overhead. BPF programs run in the context of the
// task that triggers them, so their cost shows up in the load's own CPU.
package overhead
