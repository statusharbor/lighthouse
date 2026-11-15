package discovery

import (
	"cmp"
	"net/netip"
	"slices"
	"time"
)

// Event kinds this collector sends.
const (
	KindListenerOpen  = "listener_open"
	KindListenerClose = "listener_close"
)

// Listener is the payload of both kinds: one TCP listening address of a
// process, and who owns it.
type Listener struct {
	Port        uint16 `json:"port"`
	Addr        string `json:"addr"` // bind address, "*" for any
	NetNS       uint32 `json:"netns"`
	HostNetwork bool   `json:"host_network"` // the host's own network namespace
	PID         uint32 `json:"pid"`
	Comm        string `json:"comm"`
	Exe         string `json:"exe,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
	Pod         string `json:"pod,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Workload    string `json:"workload,omitempty"` // pod name without the rollout suffixes
	Unit        string `json:"unit,omitempty"`     // systemd service
	// Service is the identity that survives restarts: "k8s:ns/workload:port",
	// "unit:name.service:port", "container:/exe:port" or "exe:/exe:port".
	Service string `json:"service"`
	Type    string `json:"type"`    // catalog service type, "tcp" when unknown
	Monitor string `json:"monitor"` // suggested monitor: postgres, mysql, http, https or tcp
	Infra   bool   `json:"infra,omitempty"`
	// Bootstrap marks a listener that existed before the agent started.
	Bootstrap bool `json:"bootstrap,omitempty"`
	// Resync marks the hourly re-announcement of a still-open listener.
	Resync bool `json:"resync,omitempty"`
}

// listenerKey is one inventory entry. 0.0.0.0 and :: are both "*", so a
// service listening on both families is one entry (DSC-U-P4).
type listenerKey struct {
	NetNS uint32
	Addr  string
	Port  uint16
}

func keyFor(netns uint32, addr netip.Addr, port uint16) listenerKey {
	addr = addr.Unmap()
	s := addr.String()
	if addr.IsUnspecified() {
		s = "*"
	}
	return listenerKey{NetNS: netns, Addr: s, Port: port}
}

type entry struct {
	info      Listener
	sockets   map[uint64]struct{} // socket inodes; SO_REUSEPORT and IPv4+IPv6 share an entry
	announced bool
}

type emission struct {
	kind    string
	payload Listener
}

// inventory tracks listening sockets and decides what to send. A listener
// is announced at the first tick after it opened, so servers that live for
// less than one interval (test suites, short scripts) send nothing. It is
// reported closed when its last socket closes. At most max entries are
// kept; the rest are counted. Announced listeners are re-sent hourly so
// the Console recovers from a dropped close event.
type inventory struct {
	max        int
	resync     time.Duration
	entries    map[listenerKey]*entry
	byInode    map[uint64]listenerKey
	replaced   []Listener // announced owners that lost their port to another program
	overflow   uint64
	lastResync time.Time
}

func newInventory(now time.Time) *inventory {
	return &inventory{max: 200, resync: time.Hour, entries: map[listenerKey]*entry{}, byInode: map[uint64]listenerKey{}, lastResync: now}
}

// open adds a listening socket. A socket already known (the bootstrap
// snapshot and a live event for the same socket) is merged (DSC-U-P7).
func (inv *inventory) open(ino uint64, k listenerKey, info Listener) {
	if _, ok := inv.byInode[ino]; ok {
		return
	}
	info.Port, info.Addr, info.NetNS = k.Port, k.Addr, k.NetNS
	describeService(&info)
	e := inv.entries[k]
	switch {
	case e == nil:
		if len(inv.entries) >= inv.max {
			inv.overflow++
			return
		}
		e = &entry{info: info, sockets: map[uint64]struct{}{}}
		inv.entries[k] = e
	case len(e.sockets) == 0:
		// Reopened before the close was sent: a restart of the same
		// service is re-announced with its new pid and container; another
		// service taking the port closes the old one first (DSC-U-F6).
		if e.announced && e.info.Service != info.Service {
			inv.replaced = append(inv.replaced, e.info)
		}
		e.info, e.announced = info, false
	}
	e.sockets[ino] = struct{}{}
	inv.byInode[ino] = k
}

// close removes a socket; unknown inodes (sockets refused by the cap, or
// closed before the snapshot) are ignored.
func (inv *inventory) close(ino uint64) {
	k, ok := inv.byInode[ino]
	if !ok {
		return
	}
	delete(inv.byInode, ino)
	delete(inv.entries[k].sockets, ino)
}

// tick returns what to send now, ordered by port for stable batches.
func (inv *inventory) tick(now time.Time) []emission {
	resync := now.Sub(inv.lastResync) >= inv.resync
	if resync {
		inv.lastResync = now
	}
	var out []emission
	for _, l := range inv.replaced {
		out = append(out, emission{KindListenerClose, l})
	}
	inv.replaced = nil
	for k, e := range inv.entries {
		switch {
		case len(e.sockets) == 0:
			if e.announced {
				out = append(out, emission{KindListenerClose, e.info})
			}
			delete(inv.entries, k)
		case !e.announced:
			e.announced = true
			out = append(out, emission{KindListenerOpen, e.info})
			e.info.Bootstrap = false
		case resync:
			p := e.info
			p.Resync = true
			out = append(out, emission{KindListenerOpen, p})
		}
	}
	slices.SortFunc(out, func(a, b emission) int {
		return cmp.Or(cmp.Compare(a.payload.Port, b.payload.Port), cmp.Compare(a.payload.Addr, b.payload.Addr),
			cmp.Compare(a.payload.NetNS, b.payload.NetNS), cmp.Compare(a.kind, b.kind))
	})
	return out
}

func (inv *inventory) announced() int {
	n := 0
	for _, e := range inv.entries {
		if e.announced {
			n++
		}
	}
	return n
}
