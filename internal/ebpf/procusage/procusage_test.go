package procusage

import (
	"strings"
	"testing"
)

func TestQuantileMS(t *testing.T) {
	b := make([]uint64, 24)
	b[7], b[13] = 95, 5 // ~128-255 us and ~8-16 ms
	if p50, _ := quantileMS(b, 0.5); p50 != 0.256 {
		t.Errorf("p50 = %v", p50)
	}
	if p99, _ := quantileMS(b, 0.99); p99 != 16.384 {
		t.Errorf("p99 = %v", p99)
	}
	if _, ok := quantileMS(make([]uint64, 24), 0.5); ok {
		t.Error("empty histogram has a quantile")
	}
}

func TestDevName(t *testing.T) {
	if got := devName(strings.NewReader("MAJOR=259\nMINOR=0\nDEVNAME=nvme0n1\nDEVTYPE=disk\n")); got != "nvme0n1" {
		t.Errorf("got %q", got)
	}
}
