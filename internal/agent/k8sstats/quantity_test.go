package k8sstats

import (
	"math"
	"testing"
)

func TestParseCPUQuantity(t *testing.T) {
	cases := []struct {
		in   string
		want float64
		bad  bool
	}{
		{"100m", 0.1, false},
		{"1500m", 1.5, false},
		{"0.5", 0.5, false},
		{"2", 2, false},
		{"4", 4, false},
		// Bad inputs the apiserver could theoretically produce.
		{"", 0, true},
		{"abc", 0, true},
		{"-1", 0, true},
		{"-100m", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseCPUQuantity(tc.in)
			if (err != nil) != tc.bad {
				t.Fatalf("parseCPUQuantity(%q) err=%v, want bad=%v", tc.in, err, tc.bad)
			}
			if !tc.bad && math.Abs(got-tc.want) > 1e-9 {
				t.Fatalf("parseCPUQuantity(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseMemoryQuantity(t *testing.T) {
	cases := []struct {
		in   string
		want float64
		bad  bool
	}{
		// Plain.
		{"1024", 1024, false},
		// Scientific notation — node allocatable on some clusters.
		{"1e9", 1e9, false},
		// Binary suffixes (1024^k).
		{"1Ki", 1024, false},
		{"1Mi", 1024 * 1024, false},
		{"1Gi", 1024 * 1024 * 1024, false},
		{"8Gi", 8 * 1024 * 1024 * 1024, false},
		{"1024Ki", 1024 * 1024, false},
		// Decimal suffixes (1000^k).
		{"1K", 1000, false},
		{"1M", 1e6, false},
		{"1G", 1e9, false},
		// Bad inputs.
		{"", 0, true},
		{"abc", 0, true},
		{"-1", 0, true},
		// Mi vs M ambiguity — make sure we pick binary when the
		// suffix says so. "1Mi" must not parse as decimal "1M" then
		// "i" suffix.
		{"1Mib", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseMemoryQuantity(tc.in)
			if (err != nil) != tc.bad {
				t.Fatalf("parseMemoryQuantity(%q) err=%v, want bad=%v", tc.in, err, tc.bad)
			}
			if !tc.bad && math.Abs(got-tc.want) > 1e-3 {
				t.Fatalf("parseMemoryQuantity(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
