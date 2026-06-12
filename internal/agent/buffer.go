package agent

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// EventBuffer persists undelivered events to disk so the agent can flush
// them after a transient Console outage. Per design §4.3 retry policy:
//
//   1. Try to send (3 attempts, exponential backoff 1s/4s/16s).
//   2. On final failure, append batch to JSONL on disk.
//   3. On next successful send, flush oldest-first then current batch.
//
// Bounded at the last hour OR a hard byte cap, whichever fires first.
// The agent restarts get to keep the buffer (events from before the crash
// are still valuable — server's idempotency key is (monitor_id,
// agent_observed_at) so duplicates after retry are safe).
type EventBuffer struct {
	path     string
	maxAge   time.Duration
	maxBytes int64

	mu sync.Mutex

	// droppedTotal accumulates the number of buffered event lines
	// the trim path has discarded across the buffer's lifetime.
	// Exposed via DroppedTotal() so the agent's /healthz or a future
	// self-metrics endpoint can surface it. Atomic so reads from
	// the health goroutine don't need to take b.mu.
	droppedTotal atomic.Uint64
}

// Default bounds per design §7.3 (event batcher description).
const (
	DefaultBufferMaxAge   = time.Hour
	DefaultBufferMaxBytes = 10 * 1024 * 1024 // 10 MB
)

// NewEventBuffer constructs a buffer at filepath dataDir + "/event-buffer.jsonl".
// The directory is created if missing.
func NewEventBuffer(dataDir string) (*EventBuffer, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dataDir, err)
	}
	return &EventBuffer{
		path:     filepath.Join(dataDir, "event-buffer.jsonl"),
		maxAge:   DefaultBufferMaxAge,
		maxBytes: DefaultBufferMaxBytes,
	}, nil
}

// Append writes one batch to the JSONL buffer. Each line is one
// transport.EventInput preceded by a small wrapper carrying the queued-at
// timestamp (used for the maxAge cap on flush).
func (b *EventBuffer) Append(events []transport.EventInput) error {
	if len(events) == 0 {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	f, err := os.OpenFile(b.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open buffer: %w", err)
	}
	defer func() { _ = f.Close() }()

	now := time.Now().UTC()
	w := bufio.NewWriter(f)
	for _, ev := range events {
		line, err := json.Marshal(bufferedEvent{QueuedAt: now, Event: ev})
		if err != nil {
			return fmt.Errorf("marshal event: %w", err)
		}
		if _, err := w.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("write event: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush buffer: %w", err)
	}

	// Trim by size if needed. Time-based trim happens lazily on Drain.
	st, err := f.Stat()
	if err == nil && st.Size() > b.maxBytes {
		dropped, err := b.trimToBytes(b.maxBytes)
		if err != nil {
			return fmt.Errorf("trim: %w", err)
		}
		if dropped > 0 {
			// Cumulative atomic counter for the health surface; per-
			// trim Warn so an operator grep'ing the log sees the
			// event. The cumulative number tells them whether this
			// is the first such event or an ongoing pattern.
			total := b.droppedTotal.Add(uint64(dropped))
			slog.Warn("event buffer trimmed; oldest events dropped",
				"dropped_events", dropped,
				"dropped_total", total,
				"max_bytes", b.maxBytes)
		}
	}
	return nil
}

// Drain reads and removes all events from the buffer that are still inside
// the maxAge window, returning them in append order (oldest-first).
// Events older than maxAge are dropped silently — they're stale enough
// that re-sending pollutes the timeline.
//
// Staleness is keyed on agent_observed_at (when the check actually ran),
// not queued_at (when the event was last written to disk). Re-Append on
// retry refreshes queued_at, which would let an arbitrarily old event
// sneak through and surface as a current incident hours after the fact.
// agent_observed_at is the truthful "this is when the world looked like
// this" timestamp.
func (b *EventBuffer) Drain() ([]transport.EventInput, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	f, err := os.Open(b.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open buffer: %w", err)
	}
	defer func() { _ = f.Close() }()

	cutoff := time.Now().UTC().Add(-b.maxAge)
	var out []transport.EventInput
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20) // up to 1MB per line
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var be bufferedEvent
		if err := json.Unmarshal(line, &be); err != nil {
			// Corrupted lines lose individually, not the whole buffer.
			continue
		}
		if be.Event.AgentObservedAt.Before(cutoff) {
			continue
		}
		out = append(out, be.Event)
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return out, fmt.Errorf("read buffer: %w", err)
	}

	// Drain succeeded — remove the file. Subsequent Append calls recreate it.
	if err := os.Remove(b.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return out, fmt.Errorf("remove buffer: %w", err)
	}
	return out, nil
}

// IsEmpty reports whether the on-disk buffer has any data.
func (b *EventBuffer) IsEmpty() (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, err := os.Stat(b.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, err
	}
	return st.Size() == 0, nil
}

// trimToBytes drops oldest lines until the file fits in maxBytes.
// Returns the number of lines dropped so the caller can log + count
// — operators looking at "why is my agent's reporting incomplete?"
// need this signal. Caller must hold b.mu.
func (b *EventBuffer) trimToBytes(maxBytes int64) (int, error) {
	data, err := os.ReadFile(b.path)
	if err != nil {
		return 0, err
	}
	dropped := 0
	for int64(len(data)) > maxBytes {
		// Drop the oldest line.
		idx := indexOfNewline(data)
		if idx < 0 {
			// No newline found; whole buffer fits in one
			// pathologically long line. Reset to empty and count
			// the whole thing as one drop.
			data = nil
			dropped++
			break
		}
		data = data[idx+1:]
		dropped++
	}
	if err := os.WriteFile(b.path, data, 0o600); err != nil {
		return dropped, err
	}
	return dropped, nil
}

// DroppedTotal returns the cumulative number of event lines the buffer
// has discarded due to the maxBytes cap across this agent process's
// lifetime. Exposed so the health endpoint / a future self-metrics
// path can surface "the buffer is overflowing; events being lost."
func (b *EventBuffer) DroppedTotal() uint64 {
	return b.droppedTotal.Load()
}

func indexOfNewline(b []byte) int {
	for i, c := range b {
		if c == '\n' {
			return i
		}
	}
	return -1
}

type bufferedEvent struct {
	QueuedAt time.Time              `json:"queued_at"`
	Event    transport.EventInput   `json:"event"`
}
