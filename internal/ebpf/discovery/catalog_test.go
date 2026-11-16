package discovery

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		comm             string
		port             uint16
		service, monitor string
	}{
		{"postgres", 5432, "postgresql", MonitorPostgres}, // DSC-U-P1
		{"postgres", 5433, "postgresql", MonitorPostgres}, // command wins over port
		{"mysqld", 3306, "mysql", MonitorMySQL},
		{"mariadbd", 3307, "mariadb", MonitorMySQL},
		{"nginx", 80, "nginx", MonitorHTTP}, // DSC-U-P2
		{"nginx", 443, "nginx", MonitorHTTPS},
		{"traefik", 8080, "traefik", MonitorHTTP},
		{"traefik", 5432, "traefik", MonitorTCP}, // a TCP entrypoint, not HTTP
		{"traefik", 4222, "traefik", MonitorTCP},
		{"redis-server", 6380, "redis", MonitorTCP},
		{"java", 9200, "elasticsearch", MonitorHTTP},
		{"beam.smp", 5672, "rabbitmq", MonitorTCP},
		{"node", 3000, "http", MonitorHTTP},
		{"myapp", 7777, "tcp", MonitorTCP}, // DSC-U-P3
	}
	for _, tc := range cases {
		if s, m := classify(tc.comm, tc.port); s != tc.service || m != tc.monitor {
			t.Errorf("classify(%s, %d) = %s/%s, want %s/%s", tc.comm, tc.port, s, m, tc.service, tc.monitor)
		}
	}
}

func TestWorkload(t *testing.T) {
	for pod, want := range map[string]string{
		"api-7d9c6b5f4b-x2k8q": "api",                  // Deployment
		"api-5f6c8d7b9-qwrtz":  "api",                  // another ReplicaSet of it (rolling deploy)
		"node-exporter-7xk2p":  "node-exporter",        // DaemonSet
		"postgres-0":           "postgres",             // StatefulSet
		"kube-apiserver-node1": "kube-apiserver-node1", // static pod: no rollout suffix
	} {
		if got := workload(pod); got != want {
			t.Errorf("workload(%q) = %q, want %q", pod, got, want)
		}
	}
}

func TestDescribeService(t *testing.T) {
	cases := []struct {
		name string
		l    Listener
		want string
	}{
		{"pod", Listener{Port: 5432, Comm: "postgres", Pod: "pg-0", Namespace: "db", ContainerID: "abc"}, "k8s:db/pg:5432"},
		{"systemd unit", Listener{Port: 5432, Comm: "postgres", Unit: "postgresql@16-main.service", Exe: "/usr/lib/postgresql/16/bin/postgres"}, "unit:postgresql@16-main.service:5432"},
		{"container", Listener{Port: 6379, Comm: "redis-server", ContainerID: "abc", Exe: "/usr/local/bin/redis-server"}, "container:/usr/local/bin/redis-server:6379"},
		{"plain process", Listener{Port: 8080, Comm: "app", Exe: "/opt/app/bin/app"}, "exe:/opt/app/bin/app:8080"},
	}
	for _, tc := range cases {
		describeService(&tc.l)
		if tc.l.Service != tc.want {
			t.Errorf("%s: service %q, want %q", tc.name, tc.l.Service, tc.want)
		}
	}

	// Criterion 7: a restart (new pid, new container) or a rolling deploy
	// (new pod name) keeps the identity.
	a := Listener{Port: 80, Comm: "nginx", Pod: "web-7d9c6b5f4b-x2k8q", Namespace: "prod", PID: 10, ContainerID: "c1"}
	b := Listener{Port: 80, Comm: "nginx", Pod: "web-5f6c8d7b9-qwrtz", Namespace: "prod", PID: 99, ContainerID: "c2"}
	describeService(&a)
	describeService(&b)
	if a.Service != b.Service {
		t.Errorf("rolling deploy changed identity: %q vs %q", a.Service, b.Service)
	}

	d := Listener{Port: 4334, Comm: "dockerd", Exe: "/usr/bin/dockerd"}
	describeService(&d)
	if !d.Infra {
		t.Errorf("dockerd's published port not marked infrastructure: %+v", d)
	}
	shim := Listener{Port: 1, Comm: "containerd-shim"}
	describeService(&shim)
	if !shim.Infra {
		t.Error("containerd-shim not infrastructure")
	}
}
