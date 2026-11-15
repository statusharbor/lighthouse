package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/statusharbor/lighthouse/internal/transport"
)

func TestContainerRuntime(t *testing.T) {
	rootLine := func(src string) string {
		return "22 1 0:21 / /proc rw - proc proc rw\n" +
			"1 0 0:50 / / rw,relatime - overlay overlay rw,lowerdir=" + src + "\n"
	}
	cases := []struct {
		name, cgroup, mountinfo, want string
	}{
		{"bare metal v2", "0::/system.slice/lighthouse.service\n", "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n", ""},
		{"k8s containerd, cgroupns private", "0::/\n", rootLine("/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/9/fs"), "containerd"},
		{"k8s containerd v1", "12:pids:/kubepods/burstable/pod1/cri-containerd-abc\n", "", "containerd"},
		{"docker", "0::/\n", rootLine("/var/lib/docker/overlay2/l/ABC"), "docker"},
		{"docker v1 cgroup", "4:memory:/docker/0123abcd\n", "", "docker"},
		{"cri-o", "0::/kubepods.slice/crio-0123.scope\n", "", "cri-o"},
		{"podman", "0::/machine.slice/libpod-0123.scope\n", "", "podman"},
		// A non-root mount mentioning docker must not count.
		{"docker only on a side mount", "0::/\n", "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n30 1 8:1 /var/lib/docker /data rw - ext4 /dev/sda1 rw\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := containerRuntime(tc.cgroup, tc.mountinfo); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// Host facts ride heartbeats until one succeeds, then stop.
func TestSendHeartbeat_HostFactsUntilAcked(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req transport.HeartbeatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		seen = append(seen, req.HostFacts != nil)
		first := len(seen) == 1
		mu.Unlock()
		if first {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(transport.HeartbeatResponse{ConfigEtag: "e"})
	}))
	t.Cleanup(srv.Close)

	r := NewRunner(&Config{Token: "lh_test"}, transport.NewClient(srv.URL, "lh_test", ""), &fakeExecutor{}, "", "")
	r.hostFacts = &transport.HostFacts{KernelRelease: "6.1.0"}
	ctx := context.Background()
	if _, err := r.SendHeartbeat(ctx); err == nil {
		t.Fatal("first heartbeat: want error from 500")
	}
	for range 2 {
		if _, err := r.SendHeartbeat(ctx); err != nil {
			t.Fatalf("heartbeat: %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []bool{true, true, false}; !reflect.DeepEqual(seen, want) {
		t.Fatalf("host_facts present per heartbeat: got %v, want %v", seen, want)
	}
}
