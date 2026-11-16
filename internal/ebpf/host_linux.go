//go:build linux

package ebpf

import (
	"os"

	"golang.org/x/sys/unix"
)

// ProbeHost reads what Check needs. Every probe is a file read or stat; a
// failed probe leaves its field empty.
func ProbeHost() Host {
	h := Host{CgroupVersion: CgroupVersion()}
	var u unix.Utsname
	if unix.Uname(&u) == nil {
		h.KernelRelease = unix.ByteSliceToString(u.Release[:])
	}
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	h.BTF = err == nil
	st, _ := os.ReadFile("/proc/self/status")
	h.Capabilities = CapabilitiesFromStatus(string(st))
	ld, _ := os.ReadFile("/sys/kernel/security/lockdown")
	h.Lockdown = LockdownMode(string(ld))
	return h
}

// CgroupVersion reports "v2" (unified), "hybrid" (v1 with a v2 mount at
// /sys/fs/cgroup/unified) or "v1".
func CgroupVersion() string {
	var st unix.Statfs_t
	if unix.Statfs("/sys/fs/cgroup", &st) != nil {
		return ""
	}
	if st.Type == unix.CGROUP2_SUPER_MAGIC {
		return "v2"
	}
	if unix.Statfs("/sys/fs/cgroup/unified", &st) == nil && st.Type == unix.CGROUP2_SUPER_MAGIC {
		return "hybrid"
	}
	return "v1"
}
