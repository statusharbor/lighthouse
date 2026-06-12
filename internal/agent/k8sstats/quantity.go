package k8sstats

import (
	"errors"
	"strconv"
	"strings"
)

// Kubernetes resource quantities (per the apimachinery spec) come in
// two flavours and we need both — cpu like "500m" / "0.5" / "2", memory
// like "8Gi" / "1024Mi" / "1e9". The official parser lives in
// k8s.io/apimachinery which would drag in client-go's transitive
// dependency tree (the very thing this package set out to avoid), so
// we hand-roll a small parser for the subset we actually need.
//
// We accept three classes of quantity strings:
//
//   - Plain numeric: "0.5", "2", "1024", "1e9"
//   - Binary suffix: "1Ki", "1Mi", "1Gi", "1Ti", "1Pi", "1Ei" (1024^k)
//   - Decimal suffix: "500m" (only on CPU; milliunits), "1K", "1M",
//     "1G", "1T", "1P", "1E" (1000^k)
//
// Unknown suffix → ErrBadQuantity. Empty string → ErrBadQuantity.
// We deliberately don't accept negative numbers or NaN — Kubernetes
// resource quantities are always non-negative.

// ErrBadQuantity signals a malformed quantity string. The collector
// treats this as "skip this metric for this node" rather than failing
// the whole tick — a partial misconfiguration on one node shouldn't
// black out the cluster aggregate.
var ErrBadQuantity = errors.New("k8sstats: bad quantity")

// Suffix multipliers, hoisted to file scope so parseMemoryQuantity
// doesn't allocate two maps per call. Binary first, decimal second —
// "Mi" must match before "M" since they share the leading byte.
var (
	binarySuffixMul = map[string]float64{
		"Ki": 1 << 10,
		"Mi": 1 << 20,
		"Gi": 1 << 30,
		"Ti": 1 << 40,
		"Pi": 1 << 50,
		"Ei": 1 << 60,
	}
	decimalSuffixMul = map[string]float64{
		"K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18,
	}
)

// parseCPUQuantity converts a Kubernetes CPU quantity to fractional
// cores. Examples:
//
//	"100m" → 0.1
//	"0.5"  → 0.5
//	"2"    → 2
//	"1500m" → 1.5
//
// "m" (milli) is by far the most common suffix on CPU — pod limits
// are usually written in millicores. Plain integers and decimals are
// what shows up in node allocatable.
func parseCPUQuantity(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, ErrBadQuantity
	}
	// Milli suffix is CPU-specific. "500m" = 0.5 cores.
	if strings.HasSuffix(s, "m") {
		v, err := strconv.ParseFloat(s[:len(s)-1], 64)
		if err != nil || v < 0 {
			return 0, ErrBadQuantity
		}
		return v / 1000, nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return 0, ErrBadQuantity
	}
	return v, nil
}

// parseMemoryQuantity converts a Kubernetes memory quantity to bytes.
// Examples:
//
//	"1024"   → 1024
//	"1024Ki" → 1,048,576       (1024 * 1024)
//	"8Gi"    → 8,589,934,592   (8 * 1024^3)
//	"1G"     → 1,000,000,000   (1000^3)
//	"1e9"    → 1,000,000,000   (scientific notation)
//
// Binary suffixes (Ki / Mi / Gi / Ti / Pi / Ei) use 1024^k; decimal
// suffixes (K / M / G / T / P / E) use 1000^k. Kubernetes accepts
// both — node allocatable.memory is usually a binary quantity like
// "8000000Ki" or "32Gi".
func parseMemoryQuantity(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, ErrBadQuantity
	}
	// Try the binary suffixes first because they're a strict superset
	// of the decimal ones ("Mi" vs "M" only differs in the trailing i).
	for suf, mul := range binarySuffixMul {
		if strings.HasSuffix(s, suf) {
			v, err := strconv.ParseFloat(s[:len(s)-len(suf)], 64)
			if err != nil || v < 0 {
				return 0, ErrBadQuantity
			}
			return v * mul, nil
		}
	}
	for suf, mul := range decimalSuffixMul {
		if strings.HasSuffix(s, suf) {
			v, err := strconv.ParseFloat(s[:len(s)-len(suf)], 64)
			if err != nil || v < 0 {
				return 0, ErrBadQuantity
			}
			return v * mul, nil
		}
	}
	// No suffix — plain bytes or scientific notation.
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return 0, ErrBadQuantity
	}
	return v, nil
}
