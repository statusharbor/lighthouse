package discovery

import (
	"strings"
	"testing"
)

func TestParseProcNet(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 41234 1 0000000000000000 100 0 0 10 0
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 41235 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1538 0100007F:A2C4 01 00000000:00000000 00:00000000 00000000   999        0 51111 1 0000000000000000 20 4 30 10 -1
   3: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 100 0 0 10 0
`
	got := parseProcNet(strings.NewReader(tcp))
	if len(got) != 2 {
		t.Fatalf("got %+v, want the 2 LISTEN lines with an inode", got)
	}
	if got[0].addr.String() != "127.0.0.1" || got[0].port != 5432 || got[0].ino != 41234 {
		t.Errorf("line 0: %+v", got[0])
	}
	if got[1].addr.String() != "0.0.0.0" || got[1].port != 80 {
		t.Errorf("line 1: %+v", got[1])
	}

	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 777 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 778 1 0000000000000000 100 0 0 10 0
`
	got = parseProcNet(strings.NewReader(tcp6))
	if len(got) != 2 || got[0].addr.String() != "::" || got[0].port != 443 || got[1].addr.String() != "::1" || got[1].port != 8080 {
		t.Fatalf("tcp6: %+v", got)
	}
}

func TestSocketInode(t *testing.T) {
	if n, ok := socketInode("socket:[41234]"); !ok || n != 41234 {
		t.Errorf("socket link: %d %v", n, ok)
	}
	for _, l := range []string{"pipe:[12]", "/dev/null", "anon_inode:[eventfd]"} {
		if _, ok := socketInode(l); ok {
			t.Errorf("%q parsed as a socket", l)
		}
	}
}
