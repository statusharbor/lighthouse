package transport

import (
	"encoding/binary"
	"math"
)

// Prometheus remote_write WriteRequest encoder — hand-rolled because the
// schema is tiny (4 message types, 6 fields total) and the prometheus/prometheus
// dep is far too heavy for a public Apache-2.0 agent.
//
// Schema reference (from Prometheus protobuf definitions):
//
//	message WriteRequest {
//	  repeated TimeSeries timeseries = 1;
//	}
//	message TimeSeries {
//	  repeated Label  labels  = 1;
//	  repeated Sample samples = 2;
//	}
//	message Label {
//	  string name  = 1;
//	  string value = 2;
//	}
//	message Sample {
//	  double value     = 1;  // doubles use fixed64 wire type
//	  int64  timestamp = 2;  // milliseconds since epoch
//	}
//
// Wire types we touch:
//   - 0 (varint)     — int64 timestamp, embedded message lengths
//   - 1 (fixed64)    — double value (Prometheus standard)
//   - 2 (length-delimited) — strings, embedded messages
//
// We do NOT support Histogram, exemplars, MetricMetadata or any of the newer
// remote_write 2.0 additions. Older 1.x receivers (vminsert included) accept
// only the four messages above; that's exactly what we encode.
//
// Performance: this is the hot encode path on every batch. We reuse the
// caller-supplied scratch slice via the EncodeWriteRequest signature so the
// runner can pool a single buffer across ticks.

// EncodeWriteRequest serialises one batch of HostSample grouped into one
// TimeSeries per (name + label-set) into a WriteRequest protobuf message.
// dst is appended-to and returned — pass a fresh slice or a pooled one.
//
// The grouping logic deliberately lives here (not in the collector) because
// the encoder is the only place that needs to compute the label key, so
// keeping it local avoids exposing a second representation.
func EncodeWriteRequest(dst []byte, samples []HostSample) []byte {
	if len(samples) == 0 {
		return dst
	}
	// Group by (metric name + sorted labels). map key is the serialised label
	// fingerprint — same string would group, different ⇒ different series.
	type seriesKey struct {
		name string
		fp   string
	}
	groups := make(map[seriesKey][]HostSample, len(samples))
	for _, s := range samples {
		k := seriesKey{name: s.Name, fp: labelFingerprint(s.Labels)}
		groups[k] = append(groups[k], s)
	}

	for k, batch := range groups {
		ts := encodeTimeSeries(k.name, batch)
		// WriteRequest.timeseries = field 1, wire type 2 (length-delimited).
		dst = appendVarintTag(dst, 1, 2)
		dst = appendVarint(dst, uint64(len(ts)))
		dst = append(dst, ts...)
	}
	return dst
}

// encodeTimeSeries serialises one TimeSeries message: __name__ label first
// (Prometheus convention), then the metric's own labels in sorted order, then
// the samples.
func encodeTimeSeries(name string, samples []HostSample) []byte {
	var ts []byte

	// __name__ label always first.
	ts = appendLabel(ts, "__name__", name)

	// Take labels from the first sample (groupings have identical labels by
	// construction). Sort for deterministic output (some receivers require it).
	if len(samples) > 0 {
		keys := sortedKeys(samples[0].Labels)
		for _, k := range keys {
			ts = appendLabel(ts, k, samples[0].Labels[k])
		}
	}

	// Samples.
	for _, s := range samples {
		smp := encodeSample(s.Value, s.Timestamp)
		// TimeSeries.samples = field 2, wire type 2.
		ts = appendVarintTag(ts, 2, 2)
		ts = appendVarint(ts, uint64(len(smp)))
		ts = append(ts, smp...)
	}
	return ts
}

func appendLabel(dst []byte, name, value string) []byte {
	var lbl []byte
	// Label.name = field 1, wire type 2.
	lbl = appendVarintTag(lbl, 1, 2)
	lbl = appendVarint(lbl, uint64(len(name)))
	lbl = append(lbl, name...)
	// Label.value = field 2, wire type 2.
	lbl = appendVarintTag(lbl, 2, 2)
	lbl = appendVarint(lbl, uint64(len(value)))
	lbl = append(lbl, value...)
	// TimeSeries.labels = field 1, wire type 2.
	dst = appendVarintTag(dst, 1, 2)
	dst = appendVarint(dst, uint64(len(lbl)))
	dst = append(dst, lbl...)
	return dst
}

func encodeSample(value float64, timestampMs int64) []byte {
	var smp []byte
	// Sample.value = field 1, wire type 1 (fixed64), encoded as IEEE-754 le.
	smp = appendVarintTag(smp, 1, 1)
	smp = appendFixed64(smp, math.Float64bits(value))
	// Sample.timestamp = field 2, wire type 0 (varint).
	smp = appendVarintTag(smp, 2, 0)
	smp = appendVarint(smp, uint64(timestampMs))
	return smp
}

// appendVarintTag writes a protobuf field tag (field_number << 3 | wire_type).
func appendVarintTag(dst []byte, fieldNum, wireType uint64) []byte {
	return appendVarint(dst, fieldNum<<3|wireType)
}

// appendVarint writes a protobuf varint (LEB128-style 7-bit groups).
func appendVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// appendFixed64 writes a little-endian 64-bit value.
func appendFixed64(dst []byte, v uint64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	return append(dst, buf[:]...)
}

// labelFingerprint computes a stable group key for a label-set. Sorted by key
// so two semantically identical maps produce the same fingerprint regardless
// of map iteration order. Pipe + null bytes as separators so a value
// containing '=' or ',' can't collide with another label boundary.
func labelFingerprint(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := sortedKeys(labels)
	var b []byte
	for _, k := range keys {
		b = append(b, k...)
		b = append(b, 0) // NUL separator
		b = append(b, labels[k]...)
		b = append(b, 0)
	}
	return string(b)
}

// sortedKeys returns labels' keys in ascending order. Lifted to a helper
// because both encodeTimeSeries and labelFingerprint need the same shape.
func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Hand-rolled insertion sort — labels per series are ≤10 in practice
	// (CPU label, mount label, …); the import-free version keeps deps minimal.
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && out[j-1] > out[j] {
			out[j-1], out[j] = out[j], out[j-1]
			j--
		}
	}
	return out
}
