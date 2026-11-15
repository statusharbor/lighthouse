package usage

import (
	"fmt"
	"testing"
)

// PRC-U-P1: from 25 groups, the 10 largest and "other" with the rest.
func TestTop(t *testing.T) {
	v := map[string]float64{}
	var rest float64
	for i := 1; i <= 25; i++ {
		v[fmt.Sprintf("g%02d", i)] = float64(i * 10)
		if i <= 15 {
			rest += float64(i * 10)
		}
	}
	got := Top(v, 0)
	if len(got) != 11 || got[0].Group != "g25" || got[9].Group != "g16" || got[10].Group != OtherName || got[10].Value != rest {
		t.Fatalf("got %+v", got)
	}
}

// PRC-U-F7: on an idle host only "other" remains; under 1% is not shown.
func TestTop_Floor(t *testing.T) {
	got := Top(map[string]float64{"sshd": 0.004, "cron": 0.002}, 1.0)
	if len(got) != 1 || got[0].Group != OtherName {
		t.Fatalf("idle: %+v", got)
	}
	if got := Top(map[string]float64{}, 0); len(got) != 0 {
		t.Fatalf("empty: %+v", got)
	}
	// The host total covers what no group accounts for.
	got = Top(map[string]float64{"app": 0.5}, 2.0)
	if len(got) != 2 || got[1].Value != 1.5 {
		t.Fatalf("remainder: %+v", got)
	}
}
