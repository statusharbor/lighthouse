package agent

// flapTracker debounces noisy checks by requiring N consecutive
// same-state observations before committing the new state. The committed
// state is what drives transition events; raw observations don't.
//
// Per design §7.4:
//   - On observation matching the committed state → counter resets to 0.
//   - On observation differing from committed → counter++.
//   - When counter reaches threshold → commit, emit transition, reset.
//
// Counters are in-memory; they reset on agent restart (which also forces
// a fresh initial-sync to re-establish baseline).
//
// A threshold of 1 disables flap protection entirely — every observation
// that differs is committed immediately.
type flapTracker struct {
	threshold int
	counters  map[string]flapCounter
}

type flapCounter struct {
	candidate State
	count     int
}

func newFlapTracker(threshold int) *flapTracker {
	if threshold < 1 {
		threshold = 1
	}
	return &flapTracker{
		threshold: threshold,
		counters:  map[string]flapCounter{},
	}
}

// SetThreshold updates the agent-side threshold. Heartbeat config refresh
// (slice A8) calls this when the server reports a new value.
func (f *flapTracker) SetThreshold(n int) {
	if n < 1 {
		n = 1
	}
	f.threshold = n
}

// Observe records an observation against the committed state. Returns
// true when the threshold has been reached and the new state should be
// committed (and a transition event emitted by the caller).
//
// committedExists is false on the very first observation of a check —
// the caller has nothing to compare against and should NOT emit (initial
// dump is a separate flow).
func (f *flapTracker) Observe(checkID string, committed State, committedExists bool, observed State) (commit bool) {
	if !committedExists {
		// No prior state — caller is expected to have just done initial
		// sync. Don't track anything; the first transition starts fresh.
		delete(f.counters, checkID)
		return false
	}
	if observed == committed {
		// Steady state — clear any in-flight flap candidate.
		delete(f.counters, checkID)
		return false
	}
	c := f.counters[checkID]
	if c.candidate != observed {
		c = flapCounter{candidate: observed, count: 1}
	} else {
		c.count++
	}
	if c.count >= f.threshold {
		delete(f.counters, checkID)
		return true
	}
	f.counters[checkID] = c
	return false
}
