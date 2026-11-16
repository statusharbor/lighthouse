package ebpf

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// Batcher queues collector events for the Console. Add never blocks: the
// queue is bounded by bytes and drops the oldest events when full,
// counting them (criterion 6, FND-U-F7). Run flushes in batches of up to
// flushSize when that many are queued or every interval; a failed send
// keeps the events and retries on the next flush.
//
// ponytail: memory only. Events queued during an outage are lost if the
// agent restarts before the Console is back; add disk spill if that
// shows up in the drop counter.
type Batcher struct {
	send      func(context.Context, []transport.EBPFEnvelope) error
	maxBytes  int
	flushSize int
	interval  time.Duration

	mu      sync.Mutex
	queue   []queued
	bytes   int
	seq     int64
	dropped atomic.Uint64
	wake    chan struct{}
}

type queued struct {
	e    transport.EBPFEnvelope
	size int
}

// envelopeOverhead approximates the encoded size of an envelope without
// its payload, so the byte bound tracks real memory closely enough.
const envelopeOverhead = 192

func NewBatcher(send func(context.Context, []transport.EBPFEnvelope) error, maxBytes, flushSize int, interval time.Duration) *Batcher {
	return &Batcher{
		send: send, maxBytes: maxBytes, flushSize: flushSize, interval: interval,
		seq:  time.Now().UnixNano(),
		wake: make(chan struct{}, 1),
	}
}

// Add queues e and assigns its Seq.
func (b *Batcher) Add(e transport.EBPFEnvelope) {
	size := len(e.Payload) + envelopeOverhead
	b.mu.Lock()
	b.seq++
	e.Seq = b.seq
	b.queue = append(b.queue, queued{e: e, size: size})
	b.bytes += size
	for b.bytes > b.maxBytes && len(b.queue) > 0 {
		b.bytes -= b.queue[0].size
		b.queue = b.queue[1:]
		b.dropped.Add(1)
	}
	full := len(b.queue) >= b.flushSize
	b.mu.Unlock()
	if full {
		select {
		case b.wake <- struct{}{}:
		default:
		}
	}
}

// Dropped is the number of events discarded because the queue was full.
func (b *Batcher) Dropped() uint64 { return b.dropped.Load() }

// Run flushes until ctx is cancelled, then tries one last flush.
func (b *Batcher) Run(ctx context.Context) {
	t := time.NewTicker(b.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			final, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			b.flush(final)
			cancel()
			return
		case <-t.C:
		case <-b.wake:
		}
		b.flush(ctx)
	}
}

func (b *Batcher) flush(ctx context.Context) {
	for {
		b.mu.Lock()
		n := min(len(b.queue), b.flushSize)
		if n == 0 {
			b.mu.Unlock()
			return
		}
		batch := make([]transport.EBPFEnvelope, n)
		for i := range batch {
			batch[i] = b.queue[i].e
		}
		b.mu.Unlock()

		if err := b.send(ctx, batch); err != nil {
			return
		}

		// Drop what was sent. Add may have trimmed some of it meanwhile,
		// so remove by Seq rather than by count.
		last := batch[n-1].Seq
		b.mu.Lock()
		for len(b.queue) > 0 && b.queue[0].e.Seq <= last {
			b.bytes -= b.queue[0].size
			b.queue = b.queue[1:]
		}
		b.mu.Unlock()
	}
}
