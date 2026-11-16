package discovery

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// procListener is one LISTEN line of /proc/<pid>/net/tcp or tcp6.
type procListener struct {
	addr netip.Addr
	port uint16
	ino  uint64
}

// parseProcNet reads the listening sockets from /proc/net/tcp{,6}. The
// kernel prints addresses as 32-bit words in host byte order, which is
// little-endian on every architecture Lighthouse ships eBPF for.
func parseProcNet(r io.Reader) []procListener {
	var out []procListener
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[3] != "0A" { // 0A = TCP_LISTEN
			continue
		}
		hexAddr, hexPort, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		raw, err := hex.DecodeString(hexAddr)
		if err != nil || (len(raw) != 4 && len(raw) != 16) {
			continue
		}
		for i := 0; i < len(raw); i += 4 {
			binary.LittleEndian.PutUint32(raw[i:], binary.BigEndian.Uint32(raw[i:]))
		}
		addr, _ := netip.AddrFromSlice(raw)
		port, err1 := strconv.ParseUint(hexPort, 16, 16)
		ino, err2 := strconv.ParseUint(f[9], 10, 64)
		if err1 != nil || err2 != nil || ino == 0 {
			continue
		}
		out = append(out, procListener{addr: addr, port: uint16(port), ino: ino})
	}
	return out
}

// socketInode returns N for an fd link "socket:[N]".
func socketInode(link string) (uint64, bool) {
	s, ok := strings.CutPrefix(link, "socket:[")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 64)
	return n, err == nil
}
