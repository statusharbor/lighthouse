package discovery

import (
	"strconv"
	"strings"

	"github.com/statusharbor/lighthouse/internal/ebpf/identity"
)

// Monitor types a suggestion can propose. postgres and mysql are the
// Console's database monitors; the rest are its HTTP and TCP checks.
const (
	MonitorPostgres = "postgres"
	MonitorMySQL    = "mysql"
	MonitorHTTP     = "http"
	MonitorHTTPS    = "https"
	MonitorTCP      = "tcp"
)

type catalogEntry struct{ service, monitor string }

// byCommand wins over byPort, so postgres on 5433 is still PostgreSQL
// (DSC-U-P1). Web servers get an HTTP check, HTTPS on the TLS ports.
var byCommand = map[string]catalogEntry{
	"postgres":      {"postgresql", MonitorPostgres},
	"mysqld":        {"mysql", MonitorMySQL},
	"mariadbd":      {"mariadb", MonitorMySQL},
	"redis-server":  {"redis", MonitorTCP},
	"valkey-server": {"valkey", MonitorTCP},
	"mongod":        {"mongodb", MonitorTCP},
	"nginx":         {"nginx", MonitorHTTP},
	"apache2":       {"apache", MonitorHTTP},
	"httpd":         {"apache", MonitorHTTP},
	"caddy":         {"caddy", MonitorHTTP},
	"haproxy":       {"haproxy", MonitorHTTP},
	"traefik":       {"traefik", MonitorHTTP},
}

var byPort = map[uint16]catalogEntry{
	5432:  {"postgresql", MonitorPostgres},
	3306:  {"mysql", MonitorMySQL},
	6379:  {"redis", MonitorTCP},
	27017: {"mongodb", MonitorTCP},
	5672:  {"rabbitmq", MonitorTCP},
	15672: {"rabbitmq", MonitorHTTP}, // management UI
	9092:  {"kafka", MonitorTCP},
	9200:  {"elasticsearch", MonitorHTTP},
	80:    {"http", MonitorHTTP},
	3000:  {"http", MonitorHTTP},
	5000:  {"http", MonitorHTTP},
	8000:  {"http", MonitorHTTP},
	8080:  {"http", MonitorHTTP},
	443:   {"https", MonitorHTTPS},
	8443:  {"https", MonitorHTTPS},
}

// infrastructure are host plumbing, not services to monitor: container
// runtimes holding published ports and embedded DNS, socket activation by
// systemd, RPC and time daemons, sshd. They stay in the inventory, marked,
// and never become suggestions.
var infrastructure = map[string]bool{
	"dockerd": true, "docker-proxy": true, "containerd": true, "kubelet": true, "kube-proxy": true,
	"systemd": true, "systemd-resolve": true, "rpcbind": true, "rpc.statd": true, "chronyd": true,
	"avahi-daemon": true, "cupsd": true, "sshd": true,
}

// classify maps a command and port to a service type and the monitor to
// suggest; unknown services get a TCP check (DSC-U-P3).
func classify(comm string, port uint16) (service, monitor string) {
	e, ok := byCommand[comm]
	if ok && e.monitor == MonitorHTTP {
		// Web servers and proxies also forward plain TCP (a Traefik
		// entrypoint for Postgres or NATS): HTTP only on web ports.
		//
		// ponytail: the web ports are the byPort HTTP(S) entries; an
		// nginx site on another port gets a TCP check the user can change.
		if w := byPort[port].monitor; w != MonitorHTTP && w != MonitorHTTPS {
			e.monitor = MonitorTCP
		}
	}
	if !ok {
		e, ok = byPort[port]
	}
	if !ok {
		return "tcp", MonitorTCP
	}
	if e.monitor == MonitorHTTP && (port == 443 || port == 8443) {
		e.monitor = MonitorHTTPS // DSC-U-P2
	}
	return e.service, e.monitor
}

func workload(pod string) string { return identity.Workload(pod) }

// describeService fills the service identity, type and suggested monitor.
// The identity survives restarts and new pids (criterion 7): the
// workload for pods, the systemd unit, otherwise the executable, plus the
// port.
//
// ponytail: plain containers are identified by executable, not image (the
// agent does not talk to the container runtime), so two containers running
// the same binary on the same port count as one service.
func describeService(l *Listener) {
	l.Type, l.Monitor = classify(l.Comm, l.Port)
	l.Infra = infrastructure[l.Comm] || strings.HasPrefix(l.Comm, "containerd-shim")
	port := ":" + strconv.Itoa(int(l.Port))
	switch {
	case l.Pod != "":
		l.Workload = workload(l.Pod)
		l.Service = "k8s:" + l.Namespace + "/" + l.Workload + port
	case l.Unit != "":
		l.Service = "unit:" + l.Unit + port
	case l.ContainerID != "":
		l.Service = "container:" + l.Exe + port
	case l.Exe != "":
		l.Service = "exe:" + l.Exe + port
	default:
		l.Service = "comm:" + l.Comm + port
	}
}
