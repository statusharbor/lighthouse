package discovery

import (
	"reflect"
	"testing"
)

// ---------------------------------------------------------------------------
// fromKubeHTTPRoute - JSON projection
// ---------------------------------------------------------------------------

// Gateway-API spec: a missing path Type defaults to "PathPrefix" and a
// missing path Value defaults to "/". fromKubeHTTPRoute must apply both
// so a minimally-specified route ("hostnames: [foo], rules: [{matches:
// [{path: {}}]}]") still surfaces a probe candidate.
func TestFromKubeHTTPRoute_DefaultsMatchSpec(t *testing.T) {
	rj := httprouteJSON{}
	rj.Metadata.Namespace = "prod"
	rj.Metadata.Name = "web"
	rj.Spec.Hostnames = []string{"app.example.com"}
	rj.Spec.Rules = append(rj.Spec.Rules, struct {
		Matches []struct {
			Path struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"path"`
		} `json:"matches"`
	}{
		Matches: []struct {
			Path struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"path"`
		}{
			{}, // Path Type + Value both omitted
		},
	})

	got := fromKubeHTTPRoute(rj)
	if got.Namespace != "prod" || got.Name != "web" {
		t.Fatalf("metadata mis-projected: %+v", got)
	}
	if !reflect.DeepEqual(got.Hostnames, []string{"app.example.com"}) {
		t.Errorf("hostnames mis-projected: %v", got.Hostnames)
	}
	if len(got.Rules) != 1 || len(got.Rules[0].Matches) != 1 {
		t.Fatalf("rule shape mis-projected: %+v", got.Rules)
	}
	m := got.Rules[0].Matches[0]
	if m.Type != "PathPrefix" || m.Value != "/" {
		t.Errorf("default match = %+v, want {PathPrefix /}", m)
	}
}

// ---------------------------------------------------------------------------
// BuildSnapshot - HTTPRoute fan-out
// ---------------------------------------------------------------------------

// One hostname × multiple match paths under one rule -> one SnapshotItem
// per match, all marked https (the v1 protocol heuristic).
func TestBuildSnapshot_HTTPRouteFansHostnameAcrossMatches(t *testing.T) {
	in := map[string]*HTTPRoute{
		"prod/web": {
			Namespace: "prod", Name: "web",
			Hostnames: []string{"app.example.com"},
			Rules: []HTTPRouteRule{{
				Matches: []HTTPPathMatch{
					{Type: "PathPrefix", Value: "/api"},
					{Type: "Exact", Value: "/healthz"},
				},
			}},
		},
	}
	out := BuildSnapshot(nil, nil, in)
	if len(out) != 2 {
		t.Fatalf("want 2 items, got %d: %+v", len(out), out)
	}
	paths := map[string]bool{}
	for _, it := range out {
		if it.Kind != "httproute" {
			t.Errorf("kind = %q, want httproute", it.Kind)
		}
		if it.Host != "app.example.com" {
			t.Errorf("host = %q, want app.example.com", it.Host)
		}
		if it.Protocol != "https" {
			t.Errorf("protocol = %q, want https (default heuristic)", it.Protocol)
		}
		paths[it.Path] = true
	}
	if !paths["/api"] || !paths["/healthz"] {
		t.Errorf("missing expected paths: %v", paths)
	}
}

// Hostname × match cross-product: 2 hostnames × 1 match -> 2 items.
func TestBuildSnapshot_HTTPRouteCrossProductsHostnames(t *testing.T) {
	in := map[string]*HTTPRoute{
		"prod/web": {
			Namespace: "prod", Name: "web",
			Hostnames: []string{"a.example.com", "b.example.com"},
			Rules: []HTTPRouteRule{{
				Matches: []HTTPPathMatch{{Type: "PathPrefix", Value: "/"}},
			}},
		},
	}
	out := BuildSnapshot(nil, nil, in)
	if len(out) != 2 {
		t.Fatalf("want 2 items, got %d", len(out))
	}
}

// Wildcard hostnames cannot be probed. Drop them - mirrors the
// ImplementationSpecific Ingress path skip in spirit.
func TestBuildSnapshot_HTTPRouteSkipsWildcardHostnames(t *testing.T) {
	in := map[string]*HTTPRoute{
		"prod/web": {
			Namespace: "prod", Name: "web",
			Hostnames: []string{"*.example.com", "concrete.example.com"},
			Rules: []HTTPRouteRule{{
				Matches: []HTTPPathMatch{{Type: "PathPrefix", Value: "/"}},
			}},
		},
	}
	out := BuildSnapshot(nil, nil, in)
	if len(out) != 1 || out[0].Host != "concrete.example.com" {
		t.Fatalf("want only concrete host, got %+v", out)
	}
}

// RegularExpression matches are dropped (regex is ambiguous for a probe URL).
func TestBuildSnapshot_HTTPRouteSkipsRegexMatches(t *testing.T) {
	in := map[string]*HTTPRoute{
		"prod/web": {
			Namespace: "prod", Name: "web",
			Hostnames: []string{"app.example.com"},
			Rules: []HTTPRouteRule{{
				Matches: []HTTPPathMatch{
					{Type: "PathPrefix", Value: "/api"},
					{Type: "RegularExpression", Value: "/v[0-9]+/.*"},
				},
			}},
		},
	}
	out := BuildSnapshot(nil, nil, in)
	if len(out) != 1 || out[0].Path != "/api" {
		t.Fatalf("regex match leaked through: %+v", out)
	}
}

// System namespaces skipped wholesale (matches Ingress + Service behaviour).
func TestBuildSnapshot_HTTPRouteSkipsSystemNamespaces(t *testing.T) {
	in := map[string]*HTTPRoute{
		"kube-system/web": {
			Namespace: "kube-system", Name: "web",
			Hostnames: []string{"internal.example.com"},
			Rules: []HTTPRouteRule{{
				Matches: []HTTPPathMatch{{Type: "PathPrefix", Value: "/"}},
			}},
		},
	}
	if out := BuildSnapshot(nil, nil, in); len(out) != 0 {
		t.Fatalf("expected no items, got %+v", out)
	}
}

// Empty hostname list -> nothing surfaces. Matches Ingress's "rule.Host
// must be non-empty" skip and stops a half-configured route from
// emitting items with Host="".
func TestBuildSnapshot_HTTPRouteSkipsHostnamelessRoutes(t *testing.T) {
	in := map[string]*HTTPRoute{
		"prod/web": {
			Namespace: "prod", Name: "web",
			Hostnames: nil,
			Rules: []HTTPRouteRule{{
				Matches: []HTTPPathMatch{{Type: "PathPrefix", Value: "/"}},
			}},
		},
	}
	if out := BuildSnapshot(nil, nil, in); len(out) != 0 {
		t.Fatalf("expected no items, got %+v", out)
	}
}

// Three kinds in one snapshot - sort key vocabulary must remain stable
// (httproute < ingress < service alphabetically).
func TestBuildSnapshot_HTTPRouteSortsStably(t *testing.T) {
	ing := map[string]*Ingress{
		"prod/i": {
			Namespace: "prod", Name: "i",
			Rules: []IngressRule{{Host: "i.example.com", Paths: []IngressPath{{Path: "/", Type: "Prefix"}}}},
		},
	}
	svc := map[string]*Service{
		"prod/s": {
			Namespace: "prod", Name: "s", Type: "LoadBalancer",
			Ports: []ServicePort{{Name: "http", Port: 80, Protocol: "TCP"}},
		},
	}
	rt := map[string]*HTTPRoute{
		"prod/r": {
			Namespace: "prod", Name: "r",
			Hostnames: []string{"r.example.com"},
			Rules: []HTTPRouteRule{{
				Matches: []HTTPPathMatch{{Type: "PathPrefix", Value: "/"}},
			}},
		},
	}
	out := BuildSnapshot(ing, svc, rt)
	if len(out) != 3 {
		t.Fatalf("want 3, got %d", len(out))
	}
	// Alphabetical: "httproute" < "ingress" < "service".
	wantKinds := []string{"httproute", "ingress", "service"}
	for i, k := range wantKinds {
		if out[i].Kind != k {
			t.Errorf("idx %d: kind = %q, want %q", i, out[i].Kind, k)
		}
	}
}

// ---------------------------------------------------------------------------
// isWildcardHostname
// ---------------------------------------------------------------------------

func TestIsWildcardHostname(t *testing.T) {
	cases := map[string]bool{
		"app.example.com":          false,
		"*.example.com":            true,
		"*":                        true,
		"":                         false,
		"foo.*.example.com":        true,
		"foo-bar.baz.example.com":  false,
		"weird*char.example.com":   true, // catches anything with * for safety
	}
	for in, want := range cases {
		if got := isWildcardHostname(in); got != want {
			t.Errorf("isWildcardHostname(%q) = %v, want %v", in, got, want)
		}
	}
}
