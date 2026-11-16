package identity

import (
	"strconv"
	"strings"
)

// parseStat returns comm and starttime (field 22, USER_HZ ticks since
// boot) from /proc/<pid>/stat. comm is in parentheses and may itself
// contain spaces and ')', so fields are counted after the last ')'.
func parseStat(stat string) (comm string, startTicks uint64, ok bool) {
	open := strings.IndexByte(stat, '(')
	end := strings.LastIndexByte(stat, ')')
	if open < 0 || end < open {
		return "", 0, false
	}
	// After ") " come fields 3.. ; starttime is field 22, so index 19.
	f := strings.Fields(stat[end+1:])
	if len(f) < 20 {
		return "", 0, false
	}
	start, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return stat[open+1 : end], start, true
}

// containerFromCgroupFile resolves container and pod from the contents of
// /proc/<pid>/cgroup, trying every hierarchy line (cgroup v1 has one per
// controller, v2 a single "0::" line).
func containerFromCgroupFile(content string) (containerID, podUID string) {
	for _, line := range strings.Split(content, "\n") {
		i := strings.LastIndexByte(line, ':')
		if i < 0 {
			continue
		}
		c, p := ParseCgroupPath(line[i+1:])
		if c != "" || p != "" {
			return c, p
		}
	}
	return "", ""
}

// unitFromCgroupFile returns the systemd service a process runs in (the
// innermost "*.service" of its cgroup path), "" when there is none, as for
// containers, which systemd places in scopes.
func unitFromCgroupFile(content string) string {
	for _, line := range strings.Split(content, "\n") {
		i := strings.LastIndexByte(line, ':')
		if i < 0 {
			continue
		}
		segs := strings.Split(line[i+1:], "/")
		for j := len(segs) - 1; j >= 0; j-- {
			if strings.HasSuffix(segs[j], ".service") {
				return segs[j]
			}
		}
	}
	return ""
}

// FromCgroupFile returns container, pod UID and (outside containers) the
// systemd unit from the contents of /proc/<pid>/cgroup.
func FromCgroupFile(content string) (containerID, podUID, unit string) {
	containerID, podUID = containerFromCgroupFile(content)
	if containerID == "" {
		unit = unitFromCgroupFile(content)
	}
	return containerID, podUID, unit
}
