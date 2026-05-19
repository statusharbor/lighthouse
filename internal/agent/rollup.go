package agent

import "sync"

// rollup accumulates sparse per-check telemetry between heartbeats: a value
// is recorded as checks observe it, and the whole map is drained onto each
// outgoing heartbeat and reset. The latency and cert-expiry heartbeat
// rollups are both instances of it. Safe for concurrent worker goroutines.
type rollup[T any] struct {
	mu sync.Mutex
	m  map[string]T
}

// newRollup returns an empty rollup ready to record into.
func newRollup[T any]() *rollup[T] {
	return &rollup[T]{m: map[string]T{}}
}

// record stores (or overwrites) the value for a check.
func (r *rollup[T]) record(checkID string, v T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[checkID] = v
}

// drain returns the accumulated map and resets to empty. Sparse semantics:
// only checks recorded since the previous drain appear.
func (r *rollup[T]) drain() map[string]T {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.m
	r.m = map[string]T{}
	return out
}
