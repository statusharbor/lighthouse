// Package requests turns OpenTelemetry eBPF Instrumentation (OBI) metrics
// into per-service request rate, error share and latency
// (docs/eBPF/06-passive-request-metrics.md). OBI runs as a separate
// process; Lighthouse reads its Prometheus endpoint on loopback and parses
// the text format itself, so no OTLP or Prometheus client library is
// needed.
package requests

import (
	"bufio"
	"io"
	"math"
	"strconv"
	"strings"
)

// sample is one line of the Prometheus text format.
type sample struct {
	name   string
	labels map[string]string
	value  float64
}

// parseText reads the Prometheus text exposition format. Comments, blank
// lines and malformed lines are skipped.
func parseText(r io.Reader) []sample {
	var out []sample
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		s, ok := parseLine(line)
		if ok {
			out = append(out, s)
		}
	}
	return out
}

func parseLine(line string) (sample, bool) {
	s := sample{labels: map[string]string{}}
	i := strings.IndexAny(line, "{ ")
	if i <= 0 {
		return s, false
	}
	s.name = line[:i]
	rest := line[i:]
	if rest[0] == '{' {
		end, ok := parseLabels(rest[1:], s.labels)
		if !ok {
			return s, false
		}
		rest = rest[1+end:]
	}
	f := strings.Fields(rest)
	if len(f) == 0 {
		return s, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil || math.IsNaN(v) {
		return s, false
	}
	s.value = v
	return s, true
}

// parseLabels reads k="v" pairs up to the closing brace and returns the
// index just past it.
func parseLabels(s string, into map[string]string) (int, bool) {
	i := 0
	for i < len(s) {
		switch s[i] {
		case '}':
			return i + 1, true
		case ',', ' ':
			i++
			continue
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 || i+eq+1 >= len(s) || s[i+eq+1] != '"' {
			return 0, false
		}
		key := s[i : i+eq]
		i += eq + 2
		var b strings.Builder
		for ; i < len(s) && s[i] != '"'; i++ {
			if s[i] == '\\' && i+1 < len(s) {
				i++
				switch s[i] {
				case 'n':
					b.WriteByte('\n')
				default:
					b.WriteByte(s[i])
				}
				continue
			}
			b.WriteByte(s[i])
		}
		if i >= len(s) {
			return 0, false
		}
		into[key] = b.String()
		i++ // closing quote
	}
	return 0, false
}
