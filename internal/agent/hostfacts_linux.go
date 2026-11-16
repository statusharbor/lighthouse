//go:build linux

package agent

import (
	"net"
	"os"
	"runtime"

	"github.com/statusharbor/lighthouse/internal/ebpf"
	"github.com/statusharbor/lighthouse/internal/transport"
)

// collectHostFacts gathers the fleet-survey report. Every probe is a file
// read or stat; a failed probe leaves its field empty instead of failing.
func collectHostFacts() *transport.HostFacts {
	h := ebpf.ProbeHost()
	f := &transport.HostFacts{
		KernelRelease: h.KernelRelease,
		Arch:          runtime.GOARCH,
		BTF:           h.BTF,
		CgroupVersion: h.CgroupVersion,
		Capabilities:  h.Capabilities,
	}
	cg, _ := os.ReadFile("/proc/self/cgroup")
	mi, _ := os.ReadFile("/proc/self/mountinfo")
	f.ContainerRuntime = containerRuntime(string(cg), string(mi))
	for _, s := range []struct{ path, name string }{
		{"/run/containerd/containerd.sock", "containerd"},
		{"/var/run/docker.sock", "docker"},
		{"/run/crio/crio.sock", "cri-o"},
		{"/run/podman/podman.sock", "podman"},
	} {
		if _, err := os.Stat(s.path); err == nil {
			f.HostRuntimes = append(f.HostRuntimes, s.name)
		}
	}
	f.Addresses = hostAddresses()
	return f
}

// hostAddresses returns the node address the DaemonSet passes in, or the
// host's global unicast interface addresses. In a container with its own
// network namespace the interfaces are the container's, which is why the
// chart passes the node's address.
func hostAddresses() []string {
	if ip := os.Getenv("LIGHTHOUSE_HOST_IP"); ip != "" {
		return []string{ip}
	}
	addrs, _ := net.InterfaceAddrs()
	var out []string
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.IsGlobalUnicast() && len(out) < 16 {
			out = append(out, n.IP.String())
		}
	}
	return out
}
