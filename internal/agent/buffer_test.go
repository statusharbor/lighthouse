package agent

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/statusharbor/lighthouse/internal/transport"
)

func newBuffer(t *testing.T) *EventBuffer {
	t.Helper()
	dir := t.TempDir()
	b, err := NewEventBuffer(dir)
	if err != nil {
		t.Fatalf("NewEventBuffer: %v", err)
	}
	return b
}

func makeEvent(checkID, newState string) transport.EventInput {
	return transport.EventInput{
		CheckID:         checkID,
		NewState:        newState,
		AgentObservedAt: time.Now().UTC(),
	}
}

func TestBuffer_AppendAndDrainRoundtrip(t *testing.T) {
	b := newBuffer(t)

	if err := b.Append([]transport.EventInput{
		makeEvent("c1", "down"),
		makeEvent("c2", "up"),
	}); err != nil {
		t.Fatal(err)
	}

	got, err := b.Drain()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].CheckID != "c1" || got[1].CheckID != "c2" {
		t.Errorf("order broken: %+v", got)
	}

	// File is gone after drain.
	empty, _ := b.IsEmpty()
	if !empty {
		t.Error("buffer should be empty after Drain")
	}
}

func TestBuffer_DrainEmptyIsZeroAndNoError(t *testing.T) {
	b := newBuffer(t)
	got, err := b.Drain()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

func TestBuffer_DropsEntriesOlderThanMaxAge(t *testing.T) {
	b := newBuffer(t)
	b.maxAge = 100 * time.Millisecond

	if err := b.Append([]transport.EventInput{makeEvent("old", "down")}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := b.Append([]transport.EventInput{makeEvent("fresh", "up")}); err != nil {
		t.Fatal(err)
	}

	got, err := b.Drain()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1 (old entry should be dropped)", len(got))
	}
	if got[0].CheckID != "fresh" {
		t.Errorf("kept wrong entry: %s", got[0].CheckID)
	}
}

func TestBuffer_TrimsToByteCap(t *testing.T) {
	b := newBuffer(t)
	b.maxBytes = 256 // tiny cap to force trim

	// Append enough events to overflow.
	var batch []transport.EventInput
	for i := 0; i < 10; i++ {
		batch = append(batch, makeEvent("c", "down"))
	}
	if err := b.Append(batch); err != nil {
		t.Fatal(err)
	}

	st, _ := os.Stat(b.path)
	if st.Size() > b.maxBytes {
		t.Errorf("file size %d exceeds maxBytes %d after trim", st.Size(), b.maxBytes)
	}
}

func TestBuffer_SkipsMalformedLines(t *testing.T) {
	b := newBuffer(t)

	// Hand-write some valid + a corrupted line.
	good, _ := json.Marshal(bufferedEvent{
		QueuedAt: time.Now().UTC(),
		Event:    makeEvent("good", "up"),
	})
	corrupted := []byte("{this is not valid json")
	contents := strings.Join([]string{string(good), string(corrupted), string(good)}, "\n") + "\n"
	if err := os.WriteFile(b.path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := b.Drain()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 valid events, got %d (corrupted line should be skipped, not fail the whole drain)", len(got))
	}
}

func TestBuffer_PathIsInsideDataDir(t *testing.T) {
	dir := t.TempDir()
	b, err := NewEventBuffer(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.path, dir) {
		t.Errorf("buffer path %q must be inside data dir %q", b.path, dir)
	}
	if filepath.Base(b.path) != "event-buffer.jsonl" {
		t.Errorf("buffer filename = %q", filepath.Base(b.path))
	}

	// File doesn't exist until first append.
	if _, err := os.Stat(b.path); err == nil {
		t.Error("buffer file should be lazily created on first append")
	}
}

// silence unused import warnings if test list shrinks
var _ = bufio.NewReader
