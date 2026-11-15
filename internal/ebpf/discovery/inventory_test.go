package discovery

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func pg(pid uint32) Listener {
	return Listener{PID: pid, Comm: "postgres", Exe: "/usr/lib/postgresql/16/bin/postgres"}
}

func kinds(es []emission) string {
	var b strings.Builder
	for _, e := range es {
		b.WriteString(e.kind + ":" + e.payload.Comm + ";")
	}
	return b.String()
}

func TestKeyFor(t *testing.T) {
	// DSC-U-P4: the two wildcards and the v4-mapped form are one entry.
	any4 := keyFor(1, netip.MustParseAddr("0.0.0.0"), 443)
	any6 := keyFor(1, netip.MustParseAddr("::"), 443)
	if any4 != any6 || any4.Addr != "*" {
		t.Errorf("wildcards: %+v vs %+v", any4, any6)
	}
	if k := keyFor(1, netip.MustParseAddr("::ffff:127.0.0.1"), 5432); k.Addr != "127.0.0.1" {
		t.Errorf("v4-mapped: %+v", k)
	}
}

func TestInventory_AnnounceAndClose(t *testing.T) {
	inv := newInventory(t0)
	k := listenerKey{NetNS: 1, Addr: "*", Port: 5432}
	boot := pg(100)
	boot.Bootstrap = true
	inv.open(10, k, boot)
	inv.open(10, k, pg(100))                                            // DSC-U-P7: snapshot + live event for one socket
	inv.open(11, listenerKey{NetNS: 1, Addr: "*", Port: 5432}, pg(100)) // IPv6 socket of the same service

	es := inv.tick(t0.Add(15 * time.Second))
	if len(es) != 1 || es[0].kind != KindListenerOpen || !es[0].payload.Bootstrap || es[0].payload.Port != 5432 || es[0].payload.Addr != "*" {
		t.Fatalf("first tick: %+v", es)
	}
	if es := inv.tick(t0.Add(30 * time.Second)); len(es) != 0 {
		t.Fatalf("nothing changed, got %+v", es)
	}

	inv.close(10)
	if es := inv.tick(t0.Add(45 * time.Second)); len(es) != 0 {
		t.Fatalf("one of two sockets closed, got %+v", es)
	}
	inv.close(11)
	inv.close(99) // unknown inode
	es = inv.tick(t0.Add(60 * time.Second))
	if kinds(es) != "listener_close:postgres;" || es[0].payload.Bootstrap {
		t.Fatalf("last socket closed: %+v", es)
	}
}

// Short-lived servers (test suites, python -m http.server for seconds)
// open and close between ticks and send nothing (DSC-E-F2).
func TestInventory_ShortLivedSendsNothing(t *testing.T) {
	inv := newInventory(t0)
	for i := range uint64(300) {
		k := listenerKey{NetNS: 1, Addr: "127.0.0.1", Port: uint16(40000 + i)}
		inv.open(1000+i, k, Listener{PID: 7, Comm: "go-test"})
		inv.close(1000 + i)
	}
	if es := inv.tick(t0.Add(15 * time.Second)); len(es) != 0 {
		t.Fatalf("got %d emissions", len(es))
	}
	if len(inv.entries) != 0 || len(inv.byInode) != 0 {
		t.Fatalf("inventory grew: %d entries %d inodes", len(inv.entries), len(inv.byInode))
	}
}

func TestInventory_Reopen(t *testing.T) {
	inv := newInventory(t0)
	k := listenerKey{NetNS: 1, Addr: "*", Port: 80}
	inv.open(1, k, Listener{PID: 5, Comm: "nginx", Exe: "/usr/sbin/nginx"})
	inv.tick(t0.Add(15 * time.Second))

	// Restart of the same program within one interval: re-announced with
	// the new pid, no close.
	inv.close(1)
	inv.open(2, k, Listener{PID: 6, Comm: "nginx", Exe: "/usr/sbin/nginx"})
	es := inv.tick(t0.Add(30 * time.Second))
	if kinds(es) != "listener_open:nginx;" || es[0].payload.PID != 6 {
		t.Fatalf("restart: %+v", es)
	}

	// DSC-U-F6: another program takes the port: the old owner is closed.
	inv.close(2)
	inv.open(3, k, Listener{PID: 9, Comm: "caddy", Exe: "/usr/bin/caddy"})
	if got := kinds(inv.tick(t0.Add(45 * time.Second))); got != "listener_close:nginx;listener_open:caddy;" {
		t.Fatalf("takeover: %s", got)
	}
}

func TestInventory_CapAndResync(t *testing.T) {
	inv := newInventory(t0)
	inv.max = 2
	for i := range uint64(3) {
		inv.open(i+1, listenerKey{NetNS: 1, Addr: "*", Port: uint16(8000 + i)}, Listener{Comm: "app"})
	}
	if inv.overflow != 1 {
		t.Fatalf("overflow = %d, want 1", inv.overflow)
	}
	if es := inv.tick(t0.Add(15 * time.Second)); len(es) != 2 {
		t.Fatalf("announced %d, want 2", len(es))
	}
	inv.close(3) // the refused socket's close is ignored
	es := inv.tick(t0.Add(time.Hour + time.Second))
	if len(es) != 2 || !es[0].payload.Resync || es[0].kind != KindListenerOpen {
		t.Fatalf("resync: %+v", es)
	}
	if inv.announced() != 2 {
		t.Fatalf("announced() = %d", inv.announced())
	}
}
