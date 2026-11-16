// Package identity keeps the process to container to pod table the eBPF
// collectors use to attribute what they see (docs/eBPF/01-foundation.md,
// "Identity cache"). Processes are keyed by pid and start time, so a
// reused pid never inherits the identity of the process before it.
package identity

import (
	"regexp"
	"strings"
)

var (
	// <runtime>-<id>.scope, written by the systemd cgroup driver.
	scopeRe = regexp.MustCompile(`^(?:docker|cri-containerd|crio|libpod)-([0-9a-f]{64})\.scope$`)
	// A bare id (cgroupfs driver), optionally crio- prefixed. Only trusted
	// under a parent that marks a container, see ParseCgroupPath.
	bareRe = regexp.MustCompile(`^(?:crio-)?([0-9a-f]{64})$`)
	// pod<uid> (cgroupfs) or kubepods[-<qos>]-pod<uid with _>.slice (systemd).
	podRe = regexp.MustCompile(`^(?:kubepods(?:-[a-z]+)?-)?pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})(?:\.slice)?$`)
)

// ParseCgroupPath returns the container ID and pod UID in a cgroup path
// (the part after the last ':' of a /proc/<pid>/cgroup line). Both are ""
// for host processes. Covers Docker, containerd and CRI-O with the
// systemd and cgroupfs drivers, on cgroup v1 and v2, including paths seen
// from another cgroup namespace ("/../../kubepods...").
//
// A 64-hex segment alone is not enough: systemd transient units carry
// long hex names too, so a bare id counts only directly under "docker",
// under a pod segment, or right after ".." (FND-U-F4). The last case is
// how a sibling container looks from inside the agent's own container
// with the cgroupfs driver: "/../<id>", seen on Docker with cgroup v2.
func ParseCgroupPath(path string) (containerID, podUID string) {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if m := podRe.FindStringSubmatch(s); m != nil {
			podUID = strings.ReplaceAll(m[1], "_", "-")
			continue
		}
		if m := scopeRe.FindStringSubmatch(s); m != nil {
			containerID = m[1]
			continue
		}
		if m := bareRe.FindStringSubmatch(s); m != nil && i > 0 {
			if parent := segs[i-1]; parent == "docker" || parent == ".." || podRe.MatchString(parent) {
				containerID = m[1]
			}
		}
	}
	return containerID, podUID
}
