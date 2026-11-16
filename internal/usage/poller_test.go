package usage

import (
	"strings"
	"testing"
	"time"
)

func TestParseProcStat(t *testing.T) {
	// A command with a space and a ")" in it; utime 150, stime 50,
	// starttime 12345, rss 2560 pages.
	line := "4242 (my (weird) app) S 1 4242 4242 0 -1 4194560 100 0 0 0 150 50 0 0 20 0 3 0 12345 104857600 2560 18446744073709551615"
	st, ok := parseProcStat(line)
	if !ok || st.comm != "my (weird) app" || st.cpuTicks != 200 || st.startTicks != 12345 || st.rssPages != 2560 || st.kernelThread {
		t.Fatalf("parsed %+v %v", st, ok)
	}
	kthread := "15 (kworker/0:1) I 2 0 0 0 -1 69238880 0 0 0 0 0 7 0 0 20 0 1 0 30 0 0 18446744073709551615"
	if st, _ := parseProcStat(kthread); !st.kernelThread || st.cpuTicks != 7 {
		t.Fatalf("kernel thread: %+v", st)
	}
	if _, ok := parseProcStat("garbage"); ok {
		t.Fatal("garbage parsed")
	}
}

func TestHostBusyTicks(t *testing.T) {
	busy, total := hostBusyTicks(strings.NewReader("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3\n"))
	if busy != 150 || total != 1000 {
		t.Fatalf("busy %d total %d", busy, total)
	}
}

func TestIOStatBytes(t *testing.T) {
	io := "8:0 rbytes=4096 wbytes=8192 rios=1 wios=2 dbytes=0 dios=0\n259:0 rbytes=100 wbytes=0 rios=1 wios=0 dbytes=0 dios=0\n"
	if got := ioStatBytes(strings.NewReader(io)); got != 12388 {
		t.Fatalf("got %d", got)
	}
}

// Criterion 6: at most 11 series per resource, and CPU's "other" includes
// what the host used outside any listed group.
func TestSamples(t *testing.T) {
	cpu := map[string]float64{}
	for i := range 30 {
		cpu["process:p"+strings.Repeat("x", i)] = 0.1
	}
	got := samples(Interval{CPU: cpu}, map[string]float64{"container:abc": 1000}, 4.0, time.Unix(0, 0))
	per := map[string]int{}
	var other float64
	for _, s := range got {
		per[s.Name]++
		if s.Name == "lighthouse_top_cpu_cores" && s.Labels["group"] == OtherName {
			other = s.Value
		}
	}
	if per["lighthouse_top_cpu_cores"] != 11 || per["lighthouse_top_device_io_bytes_per_second"] != 1 {
		t.Fatalf("series per resource: %v", per)
	}
	if other < 3.0-1e-9 || other > 3.0+1e-9 { // 4 cores busy, 10 x 0.1 listed
		t.Fatalf("CPU other = %v, want 3", other)
	}
}
