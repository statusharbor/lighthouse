package incident

import (
	"testing"
	"time"
)

// INC-U-P3.
func TestConnectReason(t *testing.T) {
	for errno, want := range map[uint8]string{111: "refused", 110: "timed_out", 113: "unreachable", 101: "unreachable", 0: "aborted", 104: "other"} {
		if got := ConnectReason(errno); got != want {
			t.Errorf("ConnectReason(%d) = %q, want %q", errno, got, want)
		}
	}
}

func v4(a, b, c, d byte) [16]byte { return [16]byte{a, b, c, d} }

func TestSeriesFor(t *testing.T) {
	v6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}
	mapped := [16]byte{10: 0xff, 11: 0xff, 12: 10, 13: 0, 14: 0, 15: 5}
	cases := []struct {
		name string
		k    connKey
		want series
	}{
		{"refused connect", connKey{Addr: v4(10, 0, 0, 5), RPort: 5432, LPort: 41000, Kind: connConnectFailed, Err: 111},
			series{metric: "lighthouse_ebpf_tcp_connect_failures_total", peer: "10.0.0.5", port: "5432", direction: "out", reason: "refused"}},
		{"outbound retransmit", connKey{Addr: v4(10, 0, 0, 5), RPort: 443, LPort: 50000, Kind: connRetransmit},
			series{metric: "lighthouse_ebpf_tcp_retransmits_total", peer: "10.0.0.5", port: "443", direction: "out"}},
		{"inbound reset keeps only the server port", connKey{Addr: v4(203, 0, 113, 9), RPort: 51123, LPort: 5432, Kind: connResetSent},
			series{metric: "lighthouse_ebpf_tcp_resets_sent_total", port: "5432", direction: "in"}},
		{"ipv6", connKey{Addr: v6, IPv6: true, RPort: 6379, LPort: 40000, Kind: connResetReceived},
			series{metric: "lighthouse_ebpf_tcp_resets_received_total", peer: "2001:db8::1", port: "6379", direction: "out"}},
		{"v4-mapped on a v6 socket", connKey{Addr: mapped, IPv6: true, RPort: 80, LPort: 33000, Kind: connConnectFailed, Err: 110},
			series{metric: "lighthouse_ebpf_tcp_connect_failures_total", peer: "10.0.0.5", port: "80", direction: "out", reason: "timed_out"}},
	}
	for _, tc := range cases {
		got, ok := seriesFor(tc.k, nil)
		if !ok || got != tc.want {
			t.Errorf("%s: got %+v,%v want %+v", tc.name, got, ok, tc.want)
		}
	}
	if _, ok := seriesFor(connKey{Kind: 9}, nil); ok {
		t.Error("unknown kind must be skipped")
	}
}

// A client port outside the ephemeral range (NAT, another OS) on a
// socket whose local port is a listener is inbound, not a new series.
func TestSeriesFor_Listening(t *testing.T) {
	listening := func(p uint16) bool { return p == 8443 }
	k := connKey{Addr: v4(10, 42, 1, 2), RPort: 13344, LPort: 8443, Kind: connResetReceived}
	want := series{metric: "lighthouse_ebpf_tcp_resets_received_total", port: "8443", direction: "in"}
	if got, _ := seriesFor(k, listening); got != want {
		t.Errorf("got %+v want %+v", got, want)
	}
	// Without the listener set the port rule still decides.
	if got, _ := seriesFor(k, nil); got.direction != "out" || got.port != "13344" {
		t.Errorf("fallback: got %+v", got)
	}
	// Outbound to a port both hosts listen on stays outbound.
	out := connKey{Addr: v4(10, 0, 0, 5), RPort: 8443, LPort: 41000, Kind: connResetReceived}
	if got, _ := seriesFor(out, listening); got.direction != "out" || got.port != "8443" {
		t.Errorf("outbound: got %+v", got)
	}
}

func TestNetTotals(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	tot := newNetTotals(nil)
	tot.maxSeries = 2
	refused := connKey{Addr: v4(10, 0, 0, 5), RPort: 5432, LPort: 41000, Kind: connConnectFailed, Err: 111}
	tot.add(refused, 3, now)
	// Another client socket to the same server folds into the same series.
	tot.add(connKey{Addr: v4(10, 0, 0, 5), RPort: 5432, LPort: 41001, Kind: connConnectFailed, Err: 111}, 2, now)
	tot.add(connKey{Addr: v4(10, 0, 0, 6), RPort: 80, LPort: 41002, Kind: connRetransmit}, 1, now)
	tot.add(connKey{Addr: v4(10, 0, 0, 7), RPort: 80, LPort: 41003, Kind: connRetransmit}, 1, now) // over the cap

	got := map[string]float64{}
	tot.emit(now, func(name string, v float64, l map[string]string) { got[name+"|"+l["peer"]] = v })
	want := map[string]float64{
		"lighthouse_ebpf_tcp_connect_failures_total|10.0.0.5": 5, // cumulative across drains
		"lighthouse_ebpf_tcp_retransmits_total|10.0.0.6":      1,
		"lighthouse_ebpf_tcp_series_refused_total|":           1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}

	// Next drain adds to the total; an idle series is dropped after an hour.
	later := now.Add(61 * time.Minute)
	tot.add(refused, 1, later)
	got = map[string]float64{}
	tot.emit(later, func(name string, v float64, l map[string]string) { got[name+"|"+l["peer"]] = v })
	if got["lighthouse_ebpf_tcp_connect_failures_total|10.0.0.5"] != 6 {
		t.Errorf("total after second drain: %v", got)
	}
	if _, ok := got["lighthouse_ebpf_tcp_retransmits_total|10.0.0.6"]; ok {
		t.Errorf("idle series still emitted: %v", got)
	}
}
