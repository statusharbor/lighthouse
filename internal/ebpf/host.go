package ebpf

import (
	"math/bits"
	"strconv"
	"strings"
)

// capNames maps capability bit numbers to names (linux/capability.h).
var capNames = [...]string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
	"CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
	"CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST",
	"CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
	"CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
	"CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
	"CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
	"CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP",
	"CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM",
	"CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
	"CAP_CHECKPOINT_RESTORE",
}

// CapabilitiesFromStatus returns the effective capability names from the
// CapEff line of /proc/self/status. Bits newer than capNames come back as
// "CAP_<n>".
func CapabilitiesFromStatus(status string) []string {
	out := []string{}
	for _, line := range strings.Split(status, "\n") {
		hex, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimSpace(hex), 16, 64)
		if err != nil {
			return out
		}
		for mask != 0 {
			bit := bits.TrailingZeros64(mask)
			mask &^= 1 << bit
			if bit < len(capNames) {
				out = append(out, capNames[bit])
			} else {
				out = append(out, "CAP_"+strconv.Itoa(bit))
			}
		}
	}
	return out
}

// LockdownMode returns the bracketed (active) entry of
// /sys/kernel/security/lockdown, e.g. "none [integrity] confidentiality"
// gives "integrity".
func LockdownMode(content string) string {
	_, rest, ok := strings.Cut(content, "[")
	if !ok {
		return ""
	}
	mode, _, _ := strings.Cut(rest, "]")
	return mode
}
