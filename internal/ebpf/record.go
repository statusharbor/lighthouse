package ebpf

import (
	"encoding/binary"
	"fmt"
	"time"
)

// DecodeRecord decodes one ring buffer record into out, a fixed-size
// struct matching the C layout (both supported targets are
// little-endian). A short or malformed record returns an error; callers
// count it as a decode error and emit nothing (FND-U-F8).
func DecodeRecord[T any](raw []byte, out *T) error {
	n := binary.Size(out)
	if n < 0 {
		return fmt.Errorf("record type %T is not fixed-size", out)
	}
	if len(raw) < n {
		return fmt.Errorf("record is %d bytes, want %d", len(raw), n)
	}
	_, err := binary.Decode(raw, binary.LittleEndian, out)
	return err
}

// wallFromBoot converts a CLOCK_BOOTTIME timestamp (what
// bpf_ktime_get_boot_ns returns) to wall-clock time, given both clocks
// read now. BOOTTIME keeps counting through suspend, and the offset is
// taken at conversion time, so neither a suspend nor a clock step shifts
// events converted after it (criterion 7).
func wallFromBoot(bootNS, nowBootNS uint64, nowWall time.Time) time.Time {
	return nowWall.Add(-time.Duration(int64(nowBootNS) - int64(bootNS)))
}
