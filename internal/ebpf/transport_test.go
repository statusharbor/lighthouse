package ebpf

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// FND-U-P2: the envelope round-trips, and a reader built for an older
// schema ignores fields it does not know.
func TestEnvelope_RoundTrip(t *testing.T) {
	in := transport.EBPFEnvelope{
		Schema: SchemaVersion, HostID: "h", BootID: "b", Seq: 7, Collector: "c", Kind: "k",
		Time: time.Date(2026, 11, 14, 1, 2, 3, 4000, time.UTC), Payload: json.RawMessage(`{"x":1}`),
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out transport.EBPFEnvelope
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Time.Equal(in.Time) || out.Seq != in.Seq || string(out.Payload) != string(in.Payload) || out.Kind != in.Kind {
		t.Fatalf("round trip: got %+v, want %+v", out, in)
	}

	newer := []byte(`{"schema":2,"host_id":"h","boot_id":"b","seq":1,"collector":"c","kind":"k",` +
		`"time":"2026-11-14T00:00:00Z","payload":{},"cgroup_id":99}`)
	var old struct {
		Schema int    `json:"schema"`
		Kind   string `json:"kind"`
	}
	if err := json.Unmarshal(newer, &old); err != nil || old.Kind != "k" {
		t.Fatalf("older reader: %+v, %v", old, err)
	}
}

// FND-U-P3 and criterion 7: conversion follows the wall clock at the time
// of conversion, so a clock step or suspend before it does not shift the
// result.
func TestWallFromBoot(t *testing.T) {
	wall := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name          string
		boot, nowBoot uint64
		nowWall, want time.Time
	}{
		{"event now", 5e9, 5e9, wall, wall},
		{"event 1.5s ago", 5e9, 6.5e9, wall, wall.Add(-1500 * time.Millisecond)},
		{"after a +1h clock step", 5e9, 6e9, wall.Add(time.Hour), wall.Add(time.Hour - time.Second)},
		{"after 10 min suspend (boottime keeps counting)", 5e9, 5e9 + 600e9, wall, wall.Add(-10 * time.Minute)},
		{"event stamped slightly after the boot read", 6e9, 5e9, wall, wall.Add(time.Second)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wallFromBoot(tc.boot, tc.nowBoot, tc.nowWall); !got.Equal(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// FND-U-F8: a truncated or wrong-type record is an error, never a panic.
func TestDecodeRecord(t *testing.T) {
	type rec struct {
		Pid  uint32
		Comm [4]byte
		TS   uint64
	}
	raw := []byte{42, 0, 0, 0, 'b', 'a', 's', 'h', 1, 0, 0, 0, 0, 0, 0, 0}
	var r rec
	if err := DecodeRecord(raw, &r); err != nil || r.Pid != 42 || string(r.Comm[:]) != "bash" || r.TS != 1 {
		t.Fatalf("decode: %+v, %v", r, err)
	}
	if err := DecodeRecord(raw[:10], &r); err == nil {
		t.Fatal("truncated record decoded without error")
	}
	if err := DecodeRecord(nil, &r); err == nil {
		t.Fatal("empty record decoded without error")
	}
	var bad struct{ S string }
	if err := DecodeRecord(raw, &bad); err == nil {
		t.Fatal("variable-size type decoded without error")
	}
}

type recordingSend struct {
	mu      sync.Mutex
	batches [][]transport.EBPFEnvelope
	fail    bool
}

func (r *recordingSend) send(_ context.Context, ev []transport.EBPFEnvelope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return errors.New("console down")
	}
	r.batches = append(r.batches, ev)
	return nil
}

func (r *recordingSend) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, b := range r.batches {
		n += len(b)
	}
	return n
}

func ev() transport.EBPFEnvelope { return transport.EBPFEnvelope{Payload: json.RawMessage(`{}`)} }

// FND-U-P5: flush when flushSize events are queued, and on the interval.
func TestBatcher_FlushOnSizeAndInterval(t *testing.T) {
	rs := &recordingSend{}
	b := NewBatcher(rs.send, 1<<20, 3, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)
	b.Add(ev())
	b.Add(ev())
	time.Sleep(20 * time.Millisecond)
	if rs.total() != 0 {
		t.Fatal("flushed below flushSize before the interval")
	}
	b.Add(ev())
	waitFor(t, "size flush", func() bool { return rs.total() == 3 })

	rs2 := &recordingSend{}
	b2 := NewBatcher(rs2.send, 1<<20, 100, 10*time.Millisecond)
	go b2.Run(ctx)
	b2.Add(ev())
	waitFor(t, "interval flush", func() bool { return rs2.total() == 1 })
}

// FND-U-F7 and criterion 6: with the Console down, Add never blocks, the
// queue stays under its byte bound by dropping the oldest, the drops are
// counted, and after recovery the newest events arrive in order with
// unique, growing Seq.
func TestBatcher_BoundedWhileDown(t *testing.T) {
	rs := &recordingSend{fail: true}
	per := 2 + envelopeOverhead // payload "{}"
	b := NewBatcher(rs.send, 10*per, 4, 5*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)

	start := time.Now()
	for range 1000 {
		b.Add(ev())
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Add blocked: 1000 adds took %v", d)
	}
	b.mu.Lock()
	queued, bytes := len(b.queue), b.bytes
	b.mu.Unlock()
	if queued != 10 || bytes > 10*per {
		t.Fatalf("queue: %d events, %d bytes; want 10 and <= %d", queued, bytes, 10*per)
	}
	if b.Dropped() != 990 {
		t.Fatalf("dropped: got %d, want 990", b.Dropped())
	}

	rs.mu.Lock()
	rs.fail = false
	rs.mu.Unlock()
	waitFor(t, "delivery after recovery", func() bool { return rs.total() == 10 })
	rs.mu.Lock()
	defer rs.mu.Unlock()
	var last int64
	for _, batch := range rs.batches {
		for _, e := range batch {
			if e.Seq <= last {
				t.Fatalf("seq not increasing: %d after %d", e.Seq, last)
			}
			last = e.Seq
		}
	}
}

// Events queued at shutdown get one last flush.
func TestBatcher_FinalFlush(t *testing.T) {
	rs := &recordingSend{}
	b := NewBatcher(rs.send, 1<<20, 100, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.Run(ctx); close(done) }()
	b.Add(ev())
	cancel()
	<-done
	if rs.total() != 1 {
		t.Fatalf("final flush sent %d, want 1", rs.total())
	}
}
