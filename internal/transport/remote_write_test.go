package transport

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

// TestEncodeWriteRequest_RoundTripSingleSample decodes the encoded bytes by
// hand (no protobuf dep in the test) and checks every field. This is the
// load-bearing invariant test — if this passes, the wire shape is correct
// and any conformant remote_write receiver will accept it.
func TestEncodeWriteRequest_RoundTripSingleSample(t *testing.T) {
	got := EncodeWriteRequest(nil, []HostSample{
		{
			Name:      "cpu_busy_percent",
			Labels:    map[string]string{"host": "node-1"},
			Value:     42.5,
			Timestamp: 1_700_000_000_000,
		},
	})

	r := newProtoReader(got)
	// WriteRequest.timeseries (field 1, length-delimited)
	field, wire := r.readTag(t)
	if field != 1 || wire != 2 {
		t.Fatalf("WriteRequest top-level: field=%d wire=%d, want 1/2", field, wire)
	}
	tsBytes := r.readLengthDelimited(t)

	// Decode TimeSeries.
	ts := newProtoReader(tsBytes)

	// Expect 2 Label messages: __name__ and host (in that order).
	want := [][2]string{
		{"__name__", "cpu_busy_percent"},
		{"host", "node-1"},
	}
	for i, exp := range want {
		field, wire = ts.readTag(t)
		if field != 1 || wire != 2 {
			t.Fatalf("Label[%d] tag: field=%d wire=%d, want 1/2", i, field, wire)
		}
		lblBytes := ts.readLengthDelimited(t)
		lbl := newProtoReader(lblBytes)
		// Label.name
		f, w := lbl.readTag(t)
		if f != 1 || w != 2 {
			t.Fatalf("Label[%d].name tag: field=%d wire=%d, want 1/2", i, f, w)
		}
		if name := string(lbl.readLengthDelimited(t)); name != exp[0] {
			t.Fatalf("Label[%d].name=%q want %q", i, name, exp[0])
		}
		// Label.value
		f, w = lbl.readTag(t)
		if f != 2 || w != 2 {
			t.Fatalf("Label[%d].value tag: field=%d wire=%d, want 2/2", i, f, w)
		}
		if val := string(lbl.readLengthDelimited(t)); val != exp[1] {
			t.Fatalf("Label[%d].value=%q want %q", i, val, exp[1])
		}
	}

	// Sample.
	field, wire = ts.readTag(t)
	if field != 2 || wire != 2 {
		t.Fatalf("Sample tag: field=%d wire=%d, want 2/2", field, wire)
	}
	smpBytes := ts.readLengthDelimited(t)
	smp := newProtoReader(smpBytes)
	// Sample.value (fixed64, IEEE-754 double little-endian)
	f, w := smp.readTag(t)
	if f != 1 || w != 1 {
		t.Fatalf("Sample.value tag: field=%d wire=%d, want 1/1", f, w)
	}
	if v := math.Float64frombits(binary.LittleEndian.Uint64(smp.readN(t, 8))); v != 42.5 {
		t.Fatalf("Sample.value=%v want 42.5", v)
	}
	// Sample.timestamp (varint, int64 ms)
	f, w = smp.readTag(t)
	if f != 2 || w != 0 {
		t.Fatalf("Sample.timestamp tag: field=%d wire=%d, want 2/0", f, w)
	}
	if ts2 := smp.readVarint(t); ts2 != 1_700_000_000_000 {
		t.Fatalf("Sample.timestamp=%d want 1700000000000", ts2)
	}
}

// TestEncodeWriteRequest_GroupsByLabelSet asserts that two samples with the
// same metric+labels collapse into one TimeSeries (two Sample entries), and
// two samples with different label values produce two TimeSeries.
func TestEncodeWriteRequest_GroupsByLabelSet(t *testing.T) {
	samples := []HostSample{
		{Name: "x", Labels: map[string]string{"a": "1"}, Value: 1, Timestamp: 1},
		{Name: "x", Labels: map[string]string{"a": "1"}, Value: 2, Timestamp: 2},
		{Name: "x", Labels: map[string]string{"a": "2"}, Value: 9, Timestamp: 9},
	}
	got := EncodeWriteRequest(nil, samples)

	r := newProtoReader(got)
	var timeSeriesCount, sampleCount int
	for r.remaining() > 0 {
		field, wire := r.readTag(t)
		if field != 1 || wire != 2 {
			t.Fatalf("WriteRequest tag: field=%d wire=%d, want 1/2", field, wire)
		}
		ts := newProtoReader(r.readLengthDelimited(t))
		timeSeriesCount++
		for ts.remaining() > 0 {
			f, w := ts.readTag(t)
			payload := ts.readLengthDelimited(t)
			_ = payload
			if f == 2 && w == 2 {
				sampleCount++
			}
		}
	}
	if timeSeriesCount != 2 {
		t.Fatalf("expected 2 TimeSeries (grouped), got %d", timeSeriesCount)
	}
	if sampleCount != 3 {
		t.Fatalf("expected 3 total Samples, got %d", sampleCount)
	}
}

func TestEncodeWriteRequest_EmptyIsEmpty(t *testing.T) {
	if out := EncodeWriteRequest(nil, nil); len(out) != 0 {
		t.Fatalf("empty input must produce empty output, got %d bytes", len(out))
	}
}

func TestLabelFingerprint_StableAcrossMapOrder(t *testing.T) {
	a := labelFingerprint(map[string]string{"a": "1", "b": "2", "c": "3"})
	b := labelFingerprint(map[string]string{"c": "3", "b": "2", "a": "1"})
	if a != b {
		t.Fatalf("label fingerprint not stable across map order:\n  a=%q\n  b=%q", a, b)
	}
}

func TestLabelFingerprint_NulSeparatorPreventsCollision(t *testing.T) {
	// Without the NUL separator these would collide:
	//   a=x  b=yz   →   "axby" + "axyz"
	//   ab=x y=z    →   "abxyz"
	// The NUL byte makes them distinct.
	one := labelFingerprint(map[string]string{"a": "x", "b": "yz"})
	two := labelFingerprint(map[string]string{"ab": "x", "y": "z"})
	if one == two {
		t.Fatalf("label fingerprint collision without NUL separator: %q", one)
	}
}

// --- tiny stdlib-only protobuf reader for the tests above ---

type protoReader struct {
	buf []byte
	off int
}

func newProtoReader(b []byte) *protoReader { return &protoReader{buf: b} }
func (r *protoReader) remaining() int      { return len(r.buf) - r.off }

func (r *protoReader) readTag(t *testing.T) (field, wire uint64) {
	t.Helper()
	tag := r.readVarint(t)
	return tag >> 3, tag & 7
}

func (r *protoReader) readVarint(t *testing.T) uint64 {
	t.Helper()
	var v uint64
	var shift uint
	for {
		if r.off >= len(r.buf) {
			t.Fatalf("varint EOF")
		}
		b := r.buf[r.off]
		r.off++
		v |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return v
		}
		shift += 7
		if shift > 63 {
			t.Fatalf("varint too long")
		}
	}
}

func (r *protoReader) readLengthDelimited(t *testing.T) []byte {
	t.Helper()
	n := r.readVarint(t)
	out := r.readN(t, int(n))
	return out
}

func (r *protoReader) readN(t *testing.T, n int) []byte {
	t.Helper()
	if r.off+n > len(r.buf) {
		t.Fatalf("readN(%d) EOF", n)
	}
	out := r.buf[r.off : r.off+n]
	r.off += n
	return out
}

// fixture for tests above: ensure non-empty bytes.Buffer compile dep
var _ = bytes.Buffer{}
