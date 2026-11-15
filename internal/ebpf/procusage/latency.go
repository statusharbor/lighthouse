// Package procusage is the eBPF side of per-process attribution
// (docs/eBPF/05-per-process-attribution.md): CPU of threads that exit
// between polls, logical file I/O per process and disk latency per device.
package procusage

import (
	"bufio"
	"io"
	"strings"
)

// quantileMS returns the upper bound in ms of the bucket holding the q-th
// value; bucket i holds [2^i, 2^(i+1)) microseconds (PRC-U-P5).
func quantileMS(buckets []uint64, q float64) (float64, bool) {
	var n uint64
	for _, b := range buckets {
		n += b
	}
	if n == 0 {
		return 0, false
	}
	rank := uint64(q*float64(n-1)) + 1
	var seen uint64
	for i, b := range buckets {
		seen += b
		if seen >= rank {
			return float64(uint64(1)<<(i+1)) / 1000, true
		}
	}
	return 0, false
}

// devName reads DEVNAME from a /sys/dev/block/<major>:<minor>/uevent
// (PRC-U-P4).
func devName(uevent io.Reader) string {
	sc := bufio.NewScanner(uevent)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "DEVNAME="); ok {
			return v
		}
	}
	return ""
}
