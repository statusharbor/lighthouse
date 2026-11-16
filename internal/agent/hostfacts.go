package agent

import (
	"strings"

	"github.com/statusharbor/lighthouse/internal/transport"
)

// Container-runtime detection for the fleet survey (hostfacts_linux.go).
// Kept free of build tags so its tests run on every platform.

// runtimeMarkers maps substrings seen in /proc/self/cgroup or in the root
// entry of /proc/self/mountinfo to a container runtime. Order matters:
// containerd paths are checked before the generic docker ones because
// docker itself runs on containerd.
var runtimeMarkers = []struct{ marker, runtime string }{
	{"cri-containerd", "containerd"},
	{"io.containerd", "containerd"},
	{"crio-", "cri-o"},
	{"libpod", "podman"},
	{"/var/lib/containers/storage", "cri-o"},
	{"docker", "docker"},
}

// containerRuntime names the runtime the agent runs under, from the
// contents of /proc/self/cgroup and the root ("/") mount line of
// /proc/self/mountinfo. "" means not containerized or not recognised.
// cgroup v2 with a private cgroup namespace shows only "0::/", which is
// why the root mount is checked as well.
func containerRuntime(cgroup, mountinfo string) string {
	root := ""
	for _, line := range strings.Split(mountinfo, "\n") {
		if f := strings.Fields(line); len(f) > 4 && f[4] == "/" {
			root = line
			break
		}
	}
	for _, src := range []string{cgroup, root} {
		for _, m := range runtimeMarkers {
			if strings.Contains(src, m.marker) {
				return m.runtime
			}
		}
	}
	return ""
}

// HostFacts is the fleet-survey report this host would send (for the dry
// run).
func HostFacts() *transport.HostFacts { return collectHostFacts() }
