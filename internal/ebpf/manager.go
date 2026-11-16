package ebpf

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// Manager owns the collectors of one agent process. Each collector runs
// in its own goroutine with panic recovery and restarts with exponential
// backoff; after maxAttempts quick failures it is marked failed and left
// alone until it is switched off and on again remotely or the agent
// restarts. A collector that fails never affects the others.
//
// Planning happens once in NewManager: the local kill switch wins over
// everything and loads nothing (not even feature probes, which load tiny
// test programs); then host requirements; then feature probes. What
// remains waits for Apply with the remote flags.
type Manager struct {
	ctx     context.Context
	sinkFor func(collector string) Sink

	baseDelay   time.Duration
	maxDelay    time.Duration
	maxAttempts int
	// stableAfter resets the failure count when a run lasted this long, so
	// a collector failing once a day is not marked failed after a week.
	stableAfter time.Duration

	mu      sync.Mutex
	entries []*entry
	wg      sync.WaitGroup
}

type entry struct {
	c        Collector
	runnable bool // passed kill switch, requirements and feature probes
	status   Status
	run      *run // nil when not started
}

type run struct{ cancel context.CancelFunc }

// NewManager plans every collector against host. ctx bounds all collector
// goroutines; Stop cancels them too. sinkFor gives each collector its own
// Sink, so the agent can stamp the collector name on what it emits.
func NewManager(ctx context.Context, collectors []Collector, host Host, killSwitch bool, sinkFor func(collector string) Sink) *Manager {
	m := &Manager{
		ctx: ctx, sinkFor: sinkFor,
		baseDelay: 5 * time.Second, maxDelay: 5 * time.Minute,
		maxAttempts: 5, stableAfter: 10 * time.Minute,
	}
	for _, c := range collectors {
		e := &entry{c: c, status: Status{Collector: c.Name()}}
		e.status.State, e.status.Reason, e.status.Detail = plan(c, host, killSwitch)
		e.runnable = e.status.Reason == ReasonRemoteOff
		m.entries = append(m.entries, e)
	}
	return m
}

func plan(c Collector, host Host, killSwitch bool) (State, Reason, string) {
	if killSwitch {
		return StateDisabled, ReasonKillSwitch, ""
	}
	req := c.Requirements()
	if reason, detail := Check(req, host); reason != "" {
		return StateUnsupported, reason, detail
	}
	for _, f := range req.Features {
		if err := f.Probe(); err != nil {
			return StateUnsupported, ReasonMissingFeature, fmt.Sprintf("%s: %v", f.Name, err)
		}
	}
	return StateDisabled, ReasonRemoteOff, ""
}

// Apply starts the runnable collectors named in enabled and stops running
// ones that are not. nil or empty enabled means the feature is off for
// this Lighthouse. A failed collector stays failed while it remains
// enabled; switching it off and on again retries it.
func (m *Manager) Apply(enabled []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if !e.runnable {
			continue
		}
		want := slices.Contains(enabled, e.c.Name())
		switch {
		case want && e.run == nil:
			m.startLocked(e)
		case !want && e.run != nil:
			e.run.cancel()
			e.run = nil
			e.status = Status{Collector: e.c.Name(), State: StateDisabled, Reason: ReasonRemoteOff}
		}
	}
}

// Statuses returns the current report, in collector order.
func (m *Manager) Statuses() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, len(m.entries))
	for i, e := range m.entries {
		out[i] = e.status
	}
	return out
}

// Stop cancels every collector and waits until all have released their
// programs.
func (m *Manager) Stop() {
	m.mu.Lock()
	for _, e := range m.entries {
		if e.run != nil {
			e.run.cancel()
			e.run = nil
		}
	}
	m.mu.Unlock()
	m.wg.Wait()
}

func (m *Manager) startLocked(e *entry) {
	ctx, cancel := context.WithCancel(m.ctx)
	r := &run{cancel: cancel}
	e.run = r
	e.status = Status{Collector: e.c.Name(), State: StateRunning}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer cancel()
		m.supervise(ctx, e, r)
	}()
}

func (m *Manager) supervise(ctx context.Context, e *entry, r *run) {
	attempts := 0
	for {
		started := time.Now()
		err := m.runOnce(ctx, e, r)
		if ctx.Err() != nil {
			return // stopped on purpose; the stopper set the status
		}
		if err == nil {
			err = errors.New("returned without being stopped")
		}
		if time.Since(started) >= m.stableAfter {
			attempts = 0
		}
		attempts++
		if attempts >= m.maxAttempts {
			m.setStatus(e, r, Status{State: StateFailed, Reason: ReasonLoadFailed, Detail: err.Error()})
			return
		}
		m.setStatus(e, r, Status{State: StateDegraded, Reason: ReasonRestarting, Detail: err.Error()})
		delay := min(m.baseDelay<<(attempts-1), m.maxDelay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		m.setStatus(e, r, Status{State: StateRunning})
	}
}

func (m *Manager) runOnce(ctx context.Context, e *entry, r *run) (err error) {
	c := e.c
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return c.Run(ctx, degradableSink{m.sinkFor(c.Name()), func(detail string) {
		m.setStatus(e, r, Status{State: StateDegraded, Reason: ReasonPartial, Detail: detail})
	}})
}

// Degrader is implemented by the sink a Manager hands its collectors: a
// collector that runs without part of its kernel support calls Degrade, so
// its status says so (e.g. no socket iterator, close-time data only).
type Degrader interface {
	Degrade(detail string)
}

type degradableSink struct {
	Sink
	degrade func(detail string)
}

func (s degradableSink) Degrade(detail string) { s.degrade(detail) }

// setStatus updates e only while r is still its current run, so a
// goroutine that lost a race with Apply cannot overwrite the new status.
func (m *Manager) setStatus(e *entry, r *run, s Status) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.run == r {
		s.Collector = e.c.Name()
		e.status = s
	}
}
