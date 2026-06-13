package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// httprouteList / httprouteJSON / serviceWatchEvent siblings live here
// to keep the Gateway-API-specific surface area isolated from the older
// Ingress + Service shapes in kube.go. They share the same kubeClient.

type httprouteList struct {
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Items []httprouteJSON `json:"items"`
}

// httprouteJSON mirrors the subset of gateway.networking.k8s.io/v1
// HTTPRoute that BuildSnapshot consumes. We intentionally ignore
// parentRefs (we don't follow up to the Gateway for protocol detection
// in v1), filters, backendRefs, headers, methods, etc.
type httprouteJSON struct {
	Metadata struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Hostnames []string `json:"hostnames"`
		Rules     []struct {
			Matches []struct {
				Path struct {
					// Type and Value are pointers in the upstream API.
					// JSON-omitted fields decode to "" cleanly, which
					// then routes through the `else` arms in the path
					// classifier below.
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"path"`
			} `json:"matches"`
		} `json:"rules"`
	} `json:"spec"`
}

// httprouteAPIPath is the Gateway-API v1 collection URL. We pin v1
// rather than chasing version negotiation; Gateway API graduated v1 in
// k8s 1.30 and that's the floor the chart documents.
const httprouteAPIPath = "/apis/gateway.networking.k8s.io/v1/httproutes"

func (k *kubeClient) httprouteListURL(ns string) string {
	if ns == "" {
		return k.apiServer + httprouteAPIPath
	}
	return fmt.Sprintf("%s/apis/gateway.networking.k8s.io/v1/namespaces/%s/httproutes",
		k.apiServer, url.PathEscape(ns))
}

// errHTTPRouteCRDMissing is returned by listHTTPRoutes when the
// apiserver responds 404 on the collection URL - the canonical signal
// that Gateway API CRDs are not installed. Callers treat this as
// "Gateway-API discovery cleanly disabled for this cluster".
var errHTTPRouteCRDMissing = errors.New("kube: gateway.networking.k8s.io/v1 HTTPRoute CRD not installed")

func (k *kubeClient) listHTTPRoutes(ctx context.Context, ns string) (*httprouteList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.httprouteListURL(ns), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")
	resp, err := k.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errHTTPRouteCRDMissing
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list httproutes: %s - %s", resp.Status, string(body))
	}
	var out httprouteList
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode list: %w", err)
	}
	return &out, nil
}

type httprouteWatchEvent struct {
	Type   string        `json:"type"`
	Object httprouteJSON `json:"object"`
}

// watchHTTPRoutes mirrors watchIngresses / watchServices but on the
// Gateway-API v1 collection.
func (k *kubeClient) watchHTTPRoutes(ctx context.Context, ns, rv string, onEvent func()) error {
	u := k.httprouteListURL(ns) + "?watch=true&resourceVersion=" + url.QueryEscape(rv)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")
	hc := *k.httpc
	hc.Timeout = 0
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusGone {
		return errResourceVersionGone
	}
	if resp.StatusCode == http.StatusNotFound {
		// CRD was uninstalled between list+watch - treat the same as
		// a startup-time miss so the loop exits cleanly rather than
		// retry-storming a permanent 404.
		return errHTTPRouteCRDMissing
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("watch: %s", resp.Status)
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var ev httprouteWatchEvent
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		switch ev.Type {
		case "ADDED", "MODIFIED", "DELETED":
			onEvent()
		case "ERROR":
			return errResourceVersionGone
		}
	}
}

// fromKubeHTTPRoute projects the kube JSON shape onto the local
// HTTPRoute. Hostname normalisation (lowercasing, trim) is left to the
// downstream snapshot fan-out so the cache reflects what the apiserver
// reported.
func fromKubeHTTPRoute(rj httprouteJSON) *HTTPRoute {
	out := &HTTPRoute{
		Namespace: rj.Metadata.Namespace,
		Name:      rj.Metadata.Name,
		Hostnames: append([]string(nil), rj.Spec.Hostnames...),
	}
	for _, r := range rj.Spec.Rules {
		rule := HTTPRouteRule{}
		for _, m := range r.Matches {
			t := m.Path.Type
			if t == "" {
				// Gateway-API defaults a missing path match Type to
				// PathPrefix per the spec. Same default applies here so
				// minimally-specified routes still surface.
				t = "PathPrefix"
			}
			v := m.Path.Value
			if v == "" {
				v = "/"
			}
			rule.Matches = append(rule.Matches, HTTPPathMatch{Type: t, Value: v})
		}
		out.Rules = append(out.Rules, rule)
	}
	return out
}

// isWildcardHostname is true for hostnames that include a wildcard
// label (e.g. "*.example.com"). The Gateway-API spec allows them but
// a probe URL needs a concrete hostname, so we drop these the same
// way the Ingress branch drops ImplementationSpecific paths.
func isWildcardHostname(h string) bool {
	return strings.Contains(h, "*")
}
