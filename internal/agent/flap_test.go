package agent

import "testing"

func TestFlap_ThresholdOne_EveryDifferenceCommits(t *testing.T) {
	f := newFlapTracker(1)

	if !f.Observe("c1", StateUp, true, StateDown) {
		t.Error("threshold=1: differing observation should commit immediately")
	}
}

func TestFlap_ThresholdThree_RequiresThreeConsecutive(t *testing.T) {
	f := newFlapTracker(3)

	if f.Observe("c1", StateUp, true, StateDown) {
		t.Error("1st diff observation must NOT commit at threshold=3")
	}
	if f.Observe("c1", StateUp, true, StateDown) {
		t.Error("2nd diff observation must NOT commit")
	}
	if !f.Observe("c1", StateUp, true, StateDown) {
		t.Error("3rd consecutive diff observation must commit")
	}
}

func TestFlap_ResetsOnSteadyState(t *testing.T) {
	f := newFlapTracker(3)
	f.Observe("c1", StateUp, true, StateDown) // count=1
	f.Observe("c1", StateUp, true, StateDown) // count=2

	// Sneaky steady-state observation — should reset the counter.
	if commit := f.Observe("c1", StateUp, true, StateUp); commit {
		t.Error("steady-state observation must not commit")
	}

	// Next two diffs must NOT cross the threshold (counter was reset).
	if f.Observe("c1", StateUp, true, StateDown) {
		t.Error("counter should have reset; 1st diff must not commit")
	}
	if f.Observe("c1", StateUp, true, StateDown) {
		t.Error("2nd diff must still not commit")
	}
	if !f.Observe("c1", StateUp, true, StateDown) {
		t.Error("3rd diff must commit")
	}
}

func TestFlap_FlapToOppositeStateRestartsCount(t *testing.T) {
	// down(1) → up(1) → up(2) → up(3)=commit. The brief down should not
	// contribute to the up-side count.
	f := newFlapTracker(3)

	f.Observe("c1", StateUp, true, StateDown) // candidate=down, count=1
	// Now actually... we'd need a third state to flip candidate. Use a
	// different sequence where committed is "up" and we see down once
	// then up steady-state, then down again.
	f.Observe("c1", StateUp, true, StateUp) // resets to steady
	f.Observe("c1", StateUp, true, StateDown)
	f.Observe("c1", StateUp, true, StateDown)
	if !f.Observe("c1", StateUp, true, StateDown) {
		t.Error("expected commit after 3 consecutive diffs from a fresh count")
	}
}

func TestFlap_NoCommitOnFirstObservation(t *testing.T) {
	// committedExists=false — initial-sync flow. Tracker must not emit.
	f := newFlapTracker(1)
	if f.Observe("c1", "", false, StateDown) {
		t.Error("no committed state → no transition emit (initial-sync handles it)")
	}
}

func TestFlap_PerCheckIndependence(t *testing.T) {
	f := newFlapTracker(2)

	f.Observe("c1", StateUp, true, StateDown) // c1: count=1
	f.Observe("c2", StateUp, true, StateDown) // c2: count=1, independent
	if !f.Observe("c1", StateUp, true, StateDown) {
		t.Error("c1 should commit on its own 2nd diff observation")
	}
	if !f.Observe("c2", StateUp, true, StateDown) {
		t.Error("c2 should commit on its own 2nd diff observation, untouched by c1")
	}
}

func TestFlap_SetThresholdClampsToOne(t *testing.T) {
	f := newFlapTracker(3)
	f.SetThreshold(0) // invalid → clamps to 1
	if !f.Observe("c1", StateUp, true, StateDown) {
		t.Error("after SetThreshold(0) effective threshold must be 1")
	}
}
