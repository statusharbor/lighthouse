//go:build !linux

package ebpf

import "time"

// WallTime is only meaningful on Linux; collectors exist only there.
func WallTime(uint64) time.Time { return time.Now() }

// BootID is empty off Linux.
func BootID() string { return "" }
