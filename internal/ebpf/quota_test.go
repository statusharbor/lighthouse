package ebpf

import (
	"net/netip"
	"strconv"
	"testing"
)

func TestSetQuotas(t *testing.T) {
	defer SetQuotas(nil)
	SetQuotas(&Quotas{Destinations: 50})
	if q := Quota(); q.Destinations != 50 || q.Resolvers != DefaultQuotas.Resolvers {
		t.Fatalf("got %+v", q)
	}
	SetQuotas(nil)
	if Quota() != DefaultQuotas {
		t.Fatal("nil does not restore the defaults")
	}
}

func TestPublicLimiter(t *testing.T) {
	defer SetQuotas(nil)
	SetQuotas(&Quotas{PublicDestinations: 2})
	var p PublicLimiter
	got := []string{}
	for i := 1; i <= 4; i++ {
		got = append(got, p.Name(netip.MustParseAddr("203.0.113."+strconv.Itoa(i)), "443"))
	}
	got = append(got, p.Name(netip.MustParseAddr("203.0.113.1"), "443"), p.Name(netip.MustParseAddr("10.0.0.9"), "443"))
	want := []string{"203.0.113.1", "203.0.113.2", "public:443", "public:443", "203.0.113.1", "10.0.0.9"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestLimited(t *testing.T) {
	defer SetLimited(nil)
	SetLimited([]string{"incident"})
	if !Limited("incident") || Limited("network") {
		t.Fatal("limited set not applied")
	}
	SetLimited(nil)
	if Limited("incident") {
		t.Fatal("limited set not cleared")
	}
}
