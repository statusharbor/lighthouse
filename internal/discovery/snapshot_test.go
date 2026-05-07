package discovery

import "testing"

// ---------------------------------------------------------------------------
// Ingress
// ---------------------------------------------------------------------------

func TestBuildSnapshot_SchemeInference(t *testing.T) {
	in := map[string]*Ingress{
		"default/web": {
			Namespace: "default",
			Name:      "web",
			TLSHosts:  map[string]bool{"secure.example.com": true},
			Rules: []IngressRule{
				{Host: "secure.example.com", Paths: []IngressPath{{Path: "/", Type: "Prefix"}}},
				{Host: "plain.example.com", Paths: []IngressPath{{Path: "/", Type: "Prefix"}}},
			},
		},
	}
	out := BuildSnapshot(in, nil)
	if len(out) != 2 {
		t.Fatalf("got %d items, want 2", len(out))
	}
	for _, it := range out {
		if it.Host == "secure.example.com" && it.Protocol != "https" {
			t.Errorf("secure host protocol = %s, want https", it.Protocol)
		}
		if it.Host == "plain.example.com" && it.Protocol != "http" {
			t.Errorf("plain host protocol = %s, want http", it.Protocol)
		}
	}
}

func TestBuildSnapshot_SkipsImplementationSpecific(t *testing.T) {
	in := map[string]*Ingress{
		"default/web": {
			Namespace: "default", Name: "web",
			Rules: []IngressRule{{
				Host: "a.example.com",
				Paths: []IngressPath{
					{Path: "/", Type: "Prefix"},
					{Path: "/(.*)", Type: "ImplementationSpecific"},
				},
			}},
		},
	}
	out := BuildSnapshot(in, nil)
	if len(out) != 1 || out[0].Path != "/" {
		t.Errorf("want only /, got %+v", out)
	}
}

func TestBuildSnapshot_FansOutHostsAndPaths(t *testing.T) {
	in := map[string]*Ingress{
		"default/multi": {
			Namespace: "default", Name: "multi",
			Rules: []IngressRule{
				{Host: "a.example.com", Paths: []IngressPath{
					{Path: "/", Type: "Prefix"},
					{Path: "/api", Type: "Prefix"},
				}},
				{Host: "b.example.com", Paths: []IngressPath{
					{Path: "/", Type: "Exact"},
				}},
			},
		},
	}
	out := BuildSnapshot(in, nil)
	if len(out) != 3 {
		t.Fatalf("want 3 items, got %d", len(out))
	}
}

// ---------------------------------------------------------------------------
// Service — surfacing
// ---------------------------------------------------------------------------

func TestBuildSnapshot_ServiceLoadBalancerSurfaces(t *testing.T) {
	in := map[string]*Service{
		"prod/web": {
			Namespace: "prod", Name: "web", Type: "LoadBalancer",
			Ports: []ServicePort{{Name: "http", Port: 80, Protocol: "TCP"}},
		},
	}
	out := BuildSnapshot(nil, in)
	if len(out) != 1 {
		t.Fatalf("got %d, want 1", len(out))
	}
	got := out[0]
	if got.Kind != "service" || got.Host != "web.prod.svc.cluster.local" || got.Port != 80 || got.Protocol != "http" {
		t.Errorf("unexpected row: %+v", got)
	}
}

func TestBuildSnapshot_ServiceClusterIPSkipped(t *testing.T) {
	in := map[string]*Service{
		"prod/internal": {
			Namespace: "prod", Name: "internal", Type: "ClusterIP",
			Ports: []ServicePort{{Port: 8080, Protocol: "TCP"}},
		},
	}
	if out := BuildSnapshot(nil, in); len(out) != 0 {
		t.Errorf("ClusterIP should be skipped, got %+v", out)
	}
}

func TestBuildSnapshot_ServiceHeadlessSkipped(t *testing.T) {
	in := map[string]*Service{
		"prod/sset": {
			Namespace: "prod", Name: "sset", Type: "ClusterIP", Headless: true,
			Ports: []ServicePort{{Port: 5432, Protocol: "TCP"}},
		},
		"prod/lb": {
			Namespace: "prod", Name: "lb", Type: "LoadBalancer", Headless: true, // unusual but possible
			Ports: []ServicePort{{Port: 80, Protocol: "TCP"}},
		},
	}
	if out := BuildSnapshot(nil, in); len(out) != 0 {
		t.Errorf("headless services should be skipped, got %+v", out)
	}
}

func TestBuildSnapshot_ServiceSystemNamespaceSkipped(t *testing.T) {
	in := map[string]*Service{
		"kube-system/dns": {
			Namespace: "kube-system", Name: "kube-dns", Type: "LoadBalancer",
			Ports: []ServicePort{{Port: 53, Protocol: "UDP"}},
		},
	}
	if out := BuildSnapshot(nil, in); len(out) != 0 {
		t.Errorf("kube-system should be skipped, got %+v", out)
	}
}

func TestBuildSnapshot_ServiceNodePortSurfaces(t *testing.T) {
	in := map[string]*Service{
		"app/api": {
			Namespace: "app", Name: "api", Type: "NodePort",
			Ports: []ServicePort{{Name: "https", Port: 443, Protocol: "TCP"}},
		},
	}
	out := BuildSnapshot(nil, in)
	if len(out) != 1 || out[0].Protocol != "https" {
		t.Errorf("expected NodePort https surface, got %+v", out)
	}
}

func TestBuildSnapshot_ServiceMultiPortFanOut(t *testing.T) {
	in := map[string]*Service{
		"prod/app": {
			Namespace: "prod", Name: "app", Type: "LoadBalancer",
			Ports: []ServicePort{
				{Name: "http", Port: 80, Protocol: "TCP"},
				{Name: "metrics", Port: 9090, Protocol: "TCP"},
				{Name: "telemetry", Port: 8125, Protocol: "UDP"},
			},
		},
	}
	out := BuildSnapshot(nil, in)
	if len(out) != 3 {
		t.Fatalf("want 3 rows (one per port), got %d", len(out))
	}
}

// ---------------------------------------------------------------------------
// Service — protocol classification
// ---------------------------------------------------------------------------

func TestClassifyServicePort_Matrix(t *testing.T) {
	cases := []struct {
		p    ServicePort
		want string
	}{
		{ServicePort{Name: "http", Port: 8080, Protocol: "TCP"}, "http"},
		{ServicePort{Name: "https", Port: 8443, Protocol: "TCP"}, "https"},
		{ServicePort{Name: "", Port: 80, Protocol: "TCP"}, "http"},
		{ServicePort{Name: "", Port: 443, Protocol: "TCP"}, "https"},
		{ServicePort{Name: "postgres", Port: 5432, Protocol: "TCP"}, "tcp"},
		{ServicePort{Name: "metrics", Port: 9090, Protocol: "TCP"}, "tcp"},
		{ServicePort{Name: "dns", Port: 53, Protocol: "UDP"}, "udp"},
		{ServicePort{Name: "statsd", Port: 8125, Protocol: "UDP"}, "udp"},
		{ServicePort{Name: "sctp-svc", Port: 9999, Protocol: "SCTP"}, ""}, // skipped
	}
	for _, c := range cases {
		got := classifyServicePort(c.p)
		if got != c.want {
			t.Errorf("classify(%+v) = %q, want %q", c.p, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Mixed + sort stability
// ---------------------------------------------------------------------------

func TestBuildSnapshot_DeterministicAcrossKinds(t *testing.T) {
	ing := map[string]*Ingress{
		"prod/web": {
			Namespace: "prod", Name: "web",
			Rules: []IngressRule{{Host: "z.example.com", Paths: []IngressPath{{Path: "/", Type: "Prefix"}}}},
		},
	}
	svc := map[string]*Service{
		"prod/api": {
			Namespace: "prod", Name: "api", Type: "LoadBalancer",
			Ports: []ServicePort{{Name: "http", Port: 80, Protocol: "TCP"}},
		},
	}
	a := BuildSnapshot(ing, svc)
	b := BuildSnapshot(ing, svc)
	if !SnapshotsEqual(a, b) {
		t.Errorf("BuildSnapshot is not deterministic across kinds")
	}
	// kind sort: ingress < service
	if a[0].Kind != "ingress" || a[1].Kind != "service" {
		t.Errorf("kind sort wrong, got %v", []string{a[0].Kind, a[1].Kind})
	}
}
