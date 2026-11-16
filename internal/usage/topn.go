// Package usage attributes host resource use to processes and containers
// (docs/eBPF/05-per-process-attribution.md): per interval, the top
// consumers of CPU, memory, file I/O, device I/O and network bytes, with
// an "other" remainder so the parts add up to the total.
package usage

import (
	"cmp"
	"slices"
)

// Top-N limits: 10 entries plus "other" per resource (criterion 6);
// entries under 1% of the total are folded into "other" (PRC-U-F7).
const (
	TopN      = 10
	MinShare  = 0.01
	OtherName = "other"
)

type Entry struct {
	Group string
	Value float64
}

// Top returns the largest groups and an "other" entry holding the rest
// (omitted when zero). total is the host-level figure when known (so
// "other" also covers what no group accounts for), else the sum of values.
func Top(values map[string]float64, total float64) []Entry {
	var sum float64
	entries := make([]Entry, 0, len(values))
	for g, v := range values {
		if v > 0 {
			entries = append(entries, Entry{g, v})
			sum += v
		}
	}
	if total < sum {
		total = sum
	}
	slices.SortFunc(entries, func(a, b Entry) int { return cmp.Or(cmp.Compare(b.Value, a.Value), cmp.Compare(a.Group, b.Group)) })
	var out []Entry
	var shown float64
	for _, e := range entries {
		if len(out) == TopN || total == 0 || e.Value/total < MinShare {
			break
		}
		out = append(out, e)
		shown += e.Value
	}
	if other := total - shown; other > total*1e-9 && other > 0 {
		out = append(out, Entry{OtherName, other})
	}
	return out
}
