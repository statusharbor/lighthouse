//go:build linux && (386 || amd64 || arm64)

package agent

import "testing"

func TestCheckTarget(t *testing.T) {
	for raw, want := range map[string]string{
		"https://app.internal/health": "443 /health",
		"http://10.0.0.5:8080":        "8080 /",
		"http://10.0.0.5:8080/status": "8080 /status",
	} {
		got, ok := checkTarget(raw)
		if !ok || got.Port+" "+got.Path != want {
			t.Errorf("checkTarget(%q) = %+v %v, want %s", raw, got, ok, want)
		}
	}
	if _, ok := checkTarget("tcp://db:5432"); ok {
		t.Error("TCP check is not an HTTP target")
	}
}
