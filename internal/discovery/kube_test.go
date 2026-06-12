package discovery

import "testing"

// IsKubernetes is the agent's runtime-self-report probe — when true the
// register handshake sends `runtime: "kubernetes"` and the Console
// flips `lighthouses.allow_multi_instance` (sticky-update; see
// status-harbor docs/victoriametrics/lighthause/PLAN.md §1.3). A false
// positive flips a single-instance install to multi-instance and
// silently disables the single-active-instance protection; a false
// negative means the DaemonSet's pods will 409 each other. Both
// outcomes are bad enough to pin the behaviour in a unit test even
// though the implementation is one line.
func TestIsKubernetes_RespectsEnv(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"empty", "", false},
		{"set", "10.0.0.1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KUBERNETES_SERVICE_HOST", tc.value)
			if got := IsKubernetes(); got != tc.want {
				t.Fatalf("IsKubernetes() = %v, want %v (env=%q)", got, tc.want, tc.value)
			}
		})
	}
}
