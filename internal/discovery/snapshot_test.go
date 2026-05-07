package discovery

import "testing"

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
	out := BuildSnapshot(in)
	if len(out) != 2 {
		t.Fatalf("got %d items, want 2", len(out))
	}
	for _, it := range out {
		if it.Host == "secure.example.com" && it.Scheme != "https" {
			t.Errorf("secure host scheme = %s, want https", it.Scheme)
		}
		if it.Host == "plain.example.com" && it.Scheme != "http" {
			t.Errorf("plain host scheme = %s, want http", it.Scheme)
		}
	}
}

func TestBuildSnapshot_SkipsImplementationSpecific(t *testing.T) {
	in := map[string]*Ingress{
		"default/web": {
			Namespace: "default",
			Name:      "web",
			Rules: []IngressRule{{
				Host: "a.example.com",
				Paths: []IngressPath{
					{Path: "/", Type: "Prefix"},
					{Path: "/(.*)", Type: "ImplementationSpecific"},
				},
			}},
		},
	}
	out := BuildSnapshot(in)
	if len(out) != 1 {
		t.Fatalf("want 1 item (regex skipped), got %d", len(out))
	}
	if out[0].Path != "/" {
		t.Errorf("got path %s, want /", out[0].Path)
	}
}

func TestBuildSnapshot_FansOutHostsAndPaths(t *testing.T) {
	in := map[string]*Ingress{
		"default/multi": {
			Namespace: "default",
			Name:      "multi",
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
	out := BuildSnapshot(in)
	if len(out) != 3 {
		t.Fatalf("want 3 items (2 hosts × paths), got %d", len(out))
	}
}

func TestBuildSnapshot_DeterministicOrder(t *testing.T) {
	build := func() []SnapshotItem {
		return BuildSnapshot(map[string]*Ingress{
			"ns2/b": {Namespace: "ns2", Name: "b", Rules: []IngressRule{{Host: "z.example.com", Paths: []IngressPath{{Path: "/", Type: "Prefix"}}}}},
			"ns1/a": {Namespace: "ns1", Name: "a", Rules: []IngressRule{{Host: "a.example.com", Paths: []IngressPath{{Path: "/", Type: "Prefix"}}}}},
		})
	}
	a := build()
	b := build()
	if !SnapshotsEqual(a, b) {
		t.Errorf("BuildSnapshot is not deterministic")
	}
	if a[0].Namespace != "ns1" {
		t.Errorf("first item namespace = %s, want ns1 (sorted)", a[0].Namespace)
	}
}

func TestBuildSnapshot_SkipsEmptyHostOrPath(t *testing.T) {
	in := map[string]*Ingress{
		"default/empty": {
			Namespace: "default",
			Name:      "empty",
			Rules: []IngressRule{
				{Host: "", Paths: []IngressPath{{Path: "/", Type: "Prefix"}}},
				{Host: "a.example.com", Paths: []IngressPath{{Path: "", Type: "Prefix"}}},
				{Host: "b.example.com", Paths: []IngressPath{{Path: "/", Type: "Prefix"}}},
			},
		},
	}
	out := BuildSnapshot(in)
	if len(out) != 1 || out[0].Host != "b.example.com" {
		t.Errorf("want only b.example.com, got %+v", out)
	}
}
