//go:build linux

package agent

import "testing"

func TestCollectHostFacts_Linux(t *testing.T) {
	f := collectHostFacts()
	t.Logf("%+v", *f)
	if f.KernelRelease == "" || f.Arch == "" || f.CgroupVersion == "" {
		t.Fatalf("kernel, arch and cgroup version must be set: %+v", *f)
	}
}
