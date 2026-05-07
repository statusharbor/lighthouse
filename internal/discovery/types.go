// Package discovery watches Kubernetes Ingress resources and pushes
// snapshots of probe candidates to the Console.
//
// The agent uses the in-cluster service account to talk to the kube
// API directly — no client-go dependency. Outside a cluster the
// watcher silently disables itself.
package discovery

// Ingress is a stripped-down representation of a Kubernetes Ingress
// resource — only the fields we need to fan out into snapshot items.
type Ingress struct {
	Namespace string
	Name      string
	TLSHosts  map[string]bool // hosts with TLS termination (⇒ https)
	Rules     []IngressRule
}

// IngressRule is one host+paths combination. Path types we honor:
//   - "Exact"  — use as-is
//   - "Prefix" — use as-is
//   - "ImplementationSpecific" — skipped (regex/wildcards are
//     ambiguous for a probe URL)
type IngressRule struct {
	Host  string
	Paths []IngressPath
}

type IngressPath struct {
	Path string
	Type string // "Exact" | "Prefix" | "ImplementationSpecific"
}

// SnapshotItem is the wire shape sent to the Console; mirrors
// transport.DiscoverySnapshotItem but lives here so the package has
// no transport dep.
type SnapshotItem struct {
	Namespace   string
	IngressName string
	Host        string
	Path        string
	Scheme      string
}
