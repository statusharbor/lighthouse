package identity

import (
	"context"
	"errors"
	"testing"
	"time"
)

const (
	cid    = "4e5d0a0a6f2a3c1b9d8e7f60514233241506f7e8d9c0b1a2938475665748392a"
	uid    = "0f3c9a5e-1b2d-4c6e-8f90-a1b2c3d4e5f6"
	uidSys = "0f3c9a5e_1b2d_4c6e_8f90_a1b2c3d4e5f6"
)

// FND-U-P4 and criterion 8 (parsing side): container ID and pod UID for
// Docker, containerd and CRI-O with the systemd and cgroupfs drivers, on
// cgroup v1 and v2.
func TestParseCgroupPath(t *testing.T) {
	cases := []struct{ name, path, wantCID, wantPod string }{
		{"docker cgroupfs v1", "/docker/" + cid, cid, ""},
		{"docker systemd v2", "/system.slice/docker-" + cid + ".scope", cid, ""},
		{"podman systemd", "/machine.slice/libpod-" + cid + ".scope", cid, ""},
		{"k8s containerd systemd v2", "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + uidSys + ".slice/cri-containerd-" + cid + ".scope", cid, uid},
		{"k8s containerd guaranteed systemd", "/kubepods.slice/kubepods-pod" + uidSys + ".slice/cri-containerd-" + cid + ".scope", cid, uid},
		{"k8s containerd cgroupfs v1", "/kubepods/besteffort/pod" + uid + "/" + cid, cid, uid},
		{"k8s cri-o systemd v2", "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + uidSys + ".slice/crio-" + cid + ".scope", cid, uid},
		{"k8s cri-o cgroupfs", "/kubepods/burstable/pod" + uid + "/crio-" + cid, cid, uid},
		{"seen from another cgroup namespace", "/../../kubepods-burstable-pod" + uidSys + ".slice/cri-containerd-" + cid + ".scope", cid, uid},
		{"pod sandbox level only", "/kubepods/burstable/pod" + uid, "", uid},
		// Captured from Docker Desktop (cgroup v2, cgroupfs driver): a
		// sibling container as seen from inside the agent's container.
		{"docker sibling seen from a container", "/../" + cid, cid, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotCID, gotPod := ParseCgroupPath(tc.path)
			if gotCID != tc.wantCID || gotPod != tc.wantPod {
				t.Fatalf("got (%q, %q), want (%q, %q)", gotCID, gotPod, tc.wantCID, tc.wantPod)
			}
		})
	}
}

// FND-U-F4: host services never get a container ID, even with a long hex
// string in the unit name.
func TestParseCgroupPath_HostServices(t *testing.T) {
	for _, path := range []string{
		"/",
		"/system.slice/sshd.service",
		"/system.slice/containerd.service",
		"/user.slice/user-1000.slice/session-3.scope",
		"/system.slice/run-r" + cid[:32] + ".scope",
		"/system.slice/" + cid + ".service",
		"/system.slice/foo-" + cid + ".scope",
		"/" + cid,
		"/system.slice/" + cid,
		"/docker-" + cid + ".service",
		"/../../system.slice/" + cid + ".service",
		"/../" + cid + ".service",
	} {
		if c, p := ParseCgroupPath(path); c != "" || p != "" {
			t.Errorf("%s: got (%q, %q), want none", path, c, p)
		}
	}
}

func TestContainerFromCgroupFile(t *testing.T) {
	v1 := "12:pids:/kubepods/burstable/pod" + uid + "/" + cid + "\n" +
		"11:memory:/kubepods/burstable/pod" + uid + "/" + cid + "\n1:name=systemd:/kubepods/burstable/pod" + uid + "/" + cid + "\n"
	if c, p := containerFromCgroupFile(v1); c != cid || p != uid {
		t.Errorf("v1: got (%q, %q)", c, p)
	}
	if c, p := containerFromCgroupFile("0::/user.slice/user-1000.slice\n"); c != "" || p != "" {
		t.Errorf("host v2: got (%q, %q)", c, p)
	}
}

func TestParseStat(t *testing.T) {
	// comm with spaces and ')' must not shift the fields.
	stat := "4242 (my (weird) prog) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000 10 18446744073709551615"
	comm, start, ok := parseStat(stat)
	if !ok || comm != "my (weird) prog" || start != 98765 {
		t.Fatalf("got (%q, %d, %v)", comm, start, ok)
	}
	for _, bad := range []string{"", "1 (x) S 1", "no parens at all"} {
		if _, _, ok := parseStat(bad); ok {
			t.Errorf("parseStat(%q) ok, want failure", bad)
		}
	}
}

// The kernel key and the /proc key must agree: start_boottime in ns
// rounds down to the USER_HZ tick /proc/<pid>/stat reports.
func TestKeyFromBootNS(t *testing.T) {
	if k := KeyFromBootNS(7, 12_345_678_901); k != (Key{PID: 7, StartTicks: 1234}) {
		t.Fatalf("got %+v", k)
	}
}

// FND-U-F5: after a pid is reused, a lookup with the old start time never
// returns the new process (and vice versa); exited entries stay for the
// grace period, then go.
func TestCache_PidReuseAndGrace(t *testing.T) {
	c := NewCache(time.Minute, 10)
	old := Key{PID: 100, StartTicks: 500}
	c.Put(old, Process{Comm: "old"})
	t0 := time.Now()
	c.Exit(old, t0)
	reused := Key{PID: 100, StartTicks: 900}
	c.Put(reused, Process{Comm: "new"})

	if p, ok := c.Get(old); !ok || p.Comm != "old" {
		t.Fatalf("old key within grace: %+v %v", p, ok)
	}
	if p, ok := c.Get(reused); !ok || p.Comm != "new" {
		t.Fatalf("new key: %+v %v", p, ok)
	}
	if _, ok := c.Get(Key{PID: 100, StartTicks: 700}); ok {
		t.Fatal("unknown start time resolved")
	}
	c.Sweep(t0.Add(30 * time.Second))
	if _, ok := c.Get(old); !ok {
		t.Fatal("swept before grace")
	}
	c.Sweep(t0.Add(2 * time.Minute))
	if _, ok := c.Get(old); ok {
		t.Fatal("exited entry kept after grace")
	}
	if _, ok := c.Get(reused); !ok {
		t.Fatal("running process swept")
	}
}

func TestCache_FullRefusesNew(t *testing.T) {
	c := NewCache(time.Minute, 2)
	c.Put(Key{PID: 1}, Process{})
	c.Put(Key{PID: 2}, Process{})
	c.Put(Key{PID: 3}, Process{})
	c.Put(Key{PID: 1}, Process{Comm: "updated"}) // existing key still updates
	n, refused := c.Stats()
	if n != 2 || refused != 1 {
		t.Fatalf("entries=%d refused=%d, want 2 and 1", n, refused)
	}
	if p, _ := c.Get(Key{PID: 1}); p.Comm != "updated" {
		t.Fatal("update of existing key refused")
	}
}

func TestPodResolver(t *testing.T) {
	calls := 0
	pods := map[string]PodRef{}
	var listErr error
	r := NewPodResolver(func(context.Context) (map[string]PodRef, error) {
		calls++
		return pods, listErr
	}, time.Hour)
	ctx := context.Background()

	if _, ok := r.Resolve(ctx, ""); ok || calls != 0 {
		t.Fatal("empty uid must not list")
	}
	pods = map[string]PodRef{uid: {Name: "web-1", Namespace: "shop"}}
	if p, ok := r.Resolve(ctx, uid); !ok || p.Name != "web-1" || calls != 1 {
		t.Fatalf("first miss reloads: %+v %v calls=%d", p, ok, calls)
	}
	if _, ok := r.Resolve(ctx, uid); !ok || calls != 1 {
		t.Fatal("hit must not reload")
	}
	if _, ok := r.Resolve(ctx, "other"); ok || calls != 1 {
		t.Fatalf("miss within minRefresh must not reload: calls=%d", calls)
	}
	listErr = errors.New("forbidden")
	r.loaded = time.Time{}
	if _, ok := r.Resolve(ctx, "other"); ok {
		t.Fatal("list error resolved")
	}
	var nilResolver *PodResolver
	if _, ok := nilResolver.Resolve(ctx, uid); ok {
		t.Fatal("nil resolver resolved")
	}
}

func TestUnitFromCgroupFile(t *testing.T) {
	for content, want := range map[string]string{
		"0::/system.slice/postgresql@16-main.service\n":                              "postgresql@16-main.service",
		"0::/user.slice/user-1000.slice/user@1000.service/app.slice/myapp.service\n": "myapp.service",
		"0::/system.slice/docker-0123456789abcdef.scope\n":                           "",
		"12:pids:/system.slice/nginx.service\n0::/system.slice/nginx.service\n":      "nginx.service",
		"0::/\n": "",
	} {
		if got := unitFromCgroupFile(content); got != want {
			t.Errorf("unitFromCgroupFile(%q) = %q, want %q", content, got, want)
		}
	}
}
