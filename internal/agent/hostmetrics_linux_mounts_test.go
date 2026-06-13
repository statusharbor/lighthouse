//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestMountTable_DiscoverFiltersAndDedups exercises the full filter +
// dedup chain against a hand-crafted /proc/mounts fixture that mirrors
// GKE COS - the platform that surfaced the original bug.
func TestMountTable_DiscoverFiltersAndDedups(t *testing.T) {
	const fixture = "" +
		"overlay / overlay ro,relatime 0 0\n" +
		"proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n" +
		"tmpfs /dev tmpfs rw,nosuid,size=65536k,mode=755 0 0\n" +
		"/dev/root / ext2 ro,relatime 0 0\n" +
		"/dev/sda1 /mnt/stateful_partition ext4 rw,nosuid,nodev,noexec,relatime,commit=30 0 0\n" +
		"/dev/sda1 /var ext4 rw,nosuid,nodev,noexec,relatime,commit=30 0 0\n" +
		"/dev/sda1 /home ext4 rw,nosuid,nodev,noexec,relatime,commit=30 0 0\n" +
		"/dev/sda1 /var/lib/kubelet ext4 rw,relatime,commit=30 0 0\n" +
		"/dev/sda8 /usr/share/oem ext4 ro,nosuid,nodev,noexec,relatime 0 0\n" +
		"/dev/loop0 /snap/core ext4 rw,relatime 0 0\n"

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mounts"), []byte(fixture), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	got, err := newMountTable(dir, "").discover()
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	// Expectations:
	//   /var (shortest mountpoint for /dev/sda1; the other 3 sda1
	//        mountpoints are deduped away)
	// Skipped: overlay/, proc, tmpfs (non-/dev source), /dev/root /
	//          (ro), /dev/sda8 /usr/share/oem (ro), /dev/loop0
	//          (loopback).
	want := []string{"/var"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("discover() = %v, want %v", got, want)
	}
}

// TestMountTable_PicksHostPID1WhenContainerized covers the
// container-namespace fix: when hostRoot is set, mount discovery reads
// /proc/1/mounts (host PID 1's mount namespace), not /proc/mounts
// (caller's).
func TestMountTable_PicksHostPID1WhenContainerized(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "1"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Container-namespace view (what we should NOT read when hostRoot set).
	if err := os.WriteFile(filepath.Join(dir, "mounts"),
		[]byte("/dev/sda9 /pod-only ext4 rw 0 0\n"), 0o644); err != nil {
		t.Fatalf("write pod mounts: %v", err)
	}
	// Host view (what we should read when hostRoot set).
	if err := os.WriteFile(filepath.Join(dir, "1", "mounts"),
		[]byte("/dev/sda1 /host-real ext4 rw 0 0\n"), 0o644); err != nil {
		t.Fatalf("write host mounts: %v", err)
	}

	got, err := newMountTable(dir, "/anything-nonempty").discover()
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	want := []string{"/host-real"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("containerized discover() = %v, want %v", got, want)
	}
}

func TestMountEntry_ReadOnlyTokenized(t *testing.T) {
	// Substring match on ",ro," would false-positive on "errors=remount-ro"
	// at end-of-string or "ro" inside other opts; tokenized match must not.
	cases := []struct {
		name    string
		options string
		want    bool
	}{
		{"plain ro", "ro", true},
		{"ro first", "ro,relatime", true},
		{"ro middle", "rw,ro,nodev", true},
		{"ro last", "rw,relatime,ro", true},
		{"errors=remount-ro suffix is not ro", "rw,errors=remount-ro", false},
		{"rw only", "rw,relatime,nodev", false},
		{"no ro substring", "rw,noatime", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := mountEntry{options: tc.options}
			if got := e.isReadOnly(); got != tc.want {
				t.Fatalf("isReadOnly(%q) = %v, want %v", tc.options, got, tc.want)
			}
		})
	}
}
