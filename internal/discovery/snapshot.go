package discovery

import (
	"fmt"
	"sort"
	"strings"
)

// systemNamespaces are skipped wholesale — never user-controlled.
var systemNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
}

// BuildSnapshot fans Ingresses + Services + HTTPRoutes out into a
// sorted, deterministic snapshot. Sorting matters because the wire
// payload's diff stability is what makes change detection cheap on the
// agent side.
//
// Per design:
//   - one item per (host, path) for ingresses + httproutes
//   - one item per (svc, port) for services
//   - scheme inferred from the TLS block for ingresses
//   - HTTPRoute protocol defaults to "https" (Gateway-API leaves TLS
//     termination to the parent Gateway; the v1 implementation here
//     does not follow parentRefs, and Gateway-API installs are
//     overwhelmingly TLS-fronted - a wrong guess just costs one
//     redirected probe at adoption time)
//   - Ingress paths with type "ImplementationSpecific" are skipped
//   - HTTPRoute matches with type "RegularExpression" are skipped
//   - wildcard hostnames on HTTPRoutes are skipped (can't probe a
//     wildcard URL)
//   - items in system namespaces are skipped
//   - non-externally-facing services (ClusterIP, headless,
//     ExternalName) are skipped
func BuildSnapshot(
	ingresses map[string]*Ingress,
	services map[string]*Service,
	httproutes map[string]*HTTPRoute,
) []SnapshotItem {
	out := make([]SnapshotItem, 0, len(ingresses)+len(services)+len(httproutes))

	for _, ing := range ingresses {
		if systemNamespaces[ing.Namespace] {
			continue
		}
		for _, rule := range ing.Rules {
			if rule.Host == "" {
				continue
			}
			for _, p := range rule.Paths {
				if p.Path == "" || p.Type == "ImplementationSpecific" {
					continue
				}
				protocol := "http"
				if ing.TLSHosts[rule.Host] {
					protocol = "https"
				}
				out = append(out, SnapshotItem{
					Kind:         "ingress",
					Namespace:    ing.Namespace,
					ResourceName: ing.Name,
					Host:         rule.Host,
					Path:         p.Path,
					Protocol:     protocol,
				})
			}
		}
	}

	for _, svc := range services {
		if !serviceIsExternallyFacing(svc) {
			continue
		}
		host := fmt.Sprintf("%s.%s.svc.cluster.local", svc.Name, svc.Namespace)
		for _, p := range svc.Ports {
			protocol := classifyServicePort(p)
			if protocol == "" {
				continue // unsupported (SCTP, etc.)
			}
			out = append(out, SnapshotItem{
				Kind:         "service",
				Namespace:    svc.Namespace,
				ResourceName: svc.Name,
				Host:         host,
				Port:         p.Port,
				Protocol:     protocol,
			})
		}
	}

	for _, rt := range httproutes {
		if systemNamespaces[rt.Namespace] {
			continue
		}
		for _, host := range rt.Hostnames {
			if host == "" || isWildcardHostname(host) {
				continue
			}
			for _, rule := range rt.Rules {
				for _, m := range rule.Matches {
					if m.Type == "RegularExpression" {
						continue
					}
					if m.Value == "" {
						continue
					}
					out = append(out, SnapshotItem{
						Kind:         "httproute",
						Namespace:    rt.Namespace,
						ResourceName: rt.Name,
						Host:         host,
						Path:         m.Value,
						Protocol:     "https",
					})
				}
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// serviceIsExternallyFacing returns true when a Service is reachable
// from outside the cluster — the only kind we surface by default.
//
//   - ClusterIP / headless / ExternalName ⇒ false
//   - NodePort / LoadBalancer            ⇒ true
//   - System namespaces                  ⇒ false (never user-shipped)
func serviceIsExternallyFacing(s *Service) bool {
	if systemNamespaces[s.Namespace] {
		return false
	}
	if s.Headless {
		return false
	}
	switch s.Type {
	case "NodePort", "LoadBalancer":
		return true
	default:
		return false
	}
}

// classifyServicePort maps a Service port's name + number + kube
// protocol onto our protocol vocabulary (http|https|tcp|udp).
// Returns "" for unsupported (SCTP).
func classifyServicePort(p ServicePort) string {
	switch strings.ToUpper(p.Protocol) {
	case "UDP":
		return "udp"
	case "SCTP":
		return ""
	}
	// TCP (the kube default when unset).
	switch strings.ToLower(p.Name) {
	case "http":
		return "http"
	case "https":
		return "https"
	}
	switch p.Port {
	case 80:
		return "http"
	case 443:
		return "https"
	}
	return "tcp"
}

// SnapshotsEqual is a cheap deep-equal helper used by the watcher to
// skip no-op POSTs.
func SnapshotsEqual(a, b []SnapshotItem) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
