//go:build linux

package agent

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// mountTable reads /proc/mounts and surfaces the canonical mountpoints
// whose filesystems the agent should report per-mount disk metrics for.
//
// Design notes:
//
//   - Source-of-mounts switches with hostRoot. /proc/mounts is a symlink
//     to /proc/self/mounts; the kernel resolves `self` against the
//     reading process's mount namespace. Inside a pod that's the pod,
//     which doesn't see the host's real disks. When hostRoot is set we
//     read /proc/1/mounts instead - PID 1 in the host's PID namespace
//     is init, which sits in the host's mount namespace. Works without
//     hostPID:true because we're targeting a specific PID, not `self`.
//
//   - Filter is a positive allow on `source startsWith /dev/`. The
//     previous deny-list of fstype names was brittle - we kept finding
//     new pseudo-fs types (efivarfs, nsfs, bpf) leaking through.
//
//   - Dedup is per source device. On COS, /dev/sda1 is bind-mounted at
//     /mnt/stateful_partition AND /var AND /home AND /var/lib/kubelet;
//     emitting four identical 23%-used series labelled with different
//     mountpoints inflates cardinality without adding signal. We keep
//     the shortest mountpoint as the canonical one.
type mountTable struct {
	procRoot string
	hostRoot string
}

// newMountTable wires a discoverer. procRoot defaults to /proc when empty
// so call sites can pass through agent config unconditionally. A non-empty
// hostRoot signals "we're in a container with the host's procfs
// bind-mounted" and switches the kernel-namespace-aware read path.
func newMountTable(procRoot, hostRoot string) *mountTable {
	if procRoot == "" {
		procRoot = DefaultProcRoot
	}
	return &mountTable{procRoot: procRoot, hostRoot: hostRoot}
}

// discover returns the mountpoints to report on, in sorted order. Sort is
// for test determinism and stable label ordering on the wire - the
// downstream cardinality cap (maxMounts) is order-sensitive.
func (t *mountTable) discover() ([]string, error) {
	path := t.mountsPath()
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	bySource := make(map[string]mountEntry, 16)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		e, ok := parseMountLine(sc.Text())
		if !ok || !e.shouldReport() {
			continue
		}
		// Same source bind-mounted at several paths: keep the shortest
		// (== highest in the tree == canonical).
		if prev, seen := bySource[e.source]; !seen || len(e.mountpoint) < len(prev.mountpoint) {
			bySource[e.source] = e
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}

	out := make([]string, 0, len(bySource))
	for _, e := range bySource {
		out = append(out, e.mountpoint)
	}
	sort.Strings(out)
	return out, nil
}

// mountsPath picks the right entry into procfs - see the type comment.
func (t *mountTable) mountsPath() string {
	if t.hostRoot != "" {
		return filepath.Join(t.procRoot, "1", "mounts")
	}
	return filepath.Join(t.procRoot, "mounts")
}

// mountEntry mirrors one filter-relevant /proc/mounts line. Fields beyond
// options (dump, pass) are ignored.
type mountEntry struct {
	source     string
	mountpoint string
	fstype     string
	options    string
}

// parseMountLine extracts a mountEntry. False on malformed lines.
func parseMountLine(line string) (mountEntry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return mountEntry{}, false
	}
	return mountEntry{
		source:     fields[0],
		mountpoint: fields[1],
		fstype:     fields[2],
		options:    fields[3],
	}, true
}

// shouldReport composes the filter predicates. Keeps the policy local to
// mountEntry so future filters (size threshold, fstype-specific rules)
// land in one place.
func (e mountEntry) shouldReport() bool {
	return e.isBlockBacked() && !e.isLoopback() && !e.isReadOnly()
}

// isBlockBacked is the positive allow: a real device under /dev. Catches
// the common cases (sda, nvme0n1p1, mapper/*, vd*, mmcblk*) without
// having to enumerate them, and rejects every pseudo-fs by construction.
func (e mountEntry) isBlockBacked() bool {
	return strings.HasPrefix(e.source, "/dev/")
}

// isLoopback skips snap/squashfs loopback mounts - mounted but not
// operationally meaningful for "is the disk full".
func (e mountEntry) isLoopback() bool {
	return strings.HasPrefix(e.source, "/dev/loop")
}

// isReadOnly drops mounts the kernel will never let us fill. Tokenizes
// the comma-separated options string rather than substring-matching, so
// "ro" doesn't accidentally match e.g. "errors=remount-ro".
func (e mountEntry) isReadOnly() bool {
	for _, opt := range strings.Split(e.options, ",") {
		if opt == "ro" {
			return true
		}
	}
	return false
}
