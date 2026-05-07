package discovery

import "sort"

// BuildSnapshot fans an Ingress map out into a sorted, deterministic
// snapshot. Sorting matters because the wire payload's diff stability
// is what makes change detection cheap on the agent side.
//
// Per design:
//   - one item per (host, path) — multi-rule ingresses fan out
//   - scheme inferred from the TLS block (host listed in tls.hosts ⇒ https)
//   - paths with type "ImplementationSpecific" are skipped (regex/wildcard)
//   - paths with empty Host or empty Path are skipped (nothing to probe)
func BuildSnapshot(ingresses map[string]*Ingress) []SnapshotItem {
	out := make([]SnapshotItem, 0, len(ingresses))
	for _, ing := range ingresses {
		for _, rule := range ing.Rules {
			if rule.Host == "" {
				continue
			}
			for _, p := range rule.Paths {
				if p.Path == "" {
					continue
				}
				if p.Type == "ImplementationSpecific" {
					continue
				}
				scheme := "http"
				if ing.TLSHosts[rule.Host] {
					scheme = "https"
				}
				out = append(out, SnapshotItem{
					Namespace:   ing.Namespace,
					IngressName: ing.Name,
					Host:        rule.Host,
					Path:        p.Path,
					Scheme:      scheme,
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// SnapshotsEqual is a cheap deep-equal helper used by the watcher
// to skip no-op POSTs to the Console.
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
