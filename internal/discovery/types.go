// Package discovery watches Kubernetes Ingress and Service resources
// and pushes snapshots of probe candidates to the Console.
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

// Service is a stripped-down representation of a Kubernetes Service —
// only the fields we need to decide whether to surface and to fan out
// into per-port snapshot items.
type Service struct {
	Namespace string
	Name      string
	Type      string // "ClusterIP" | "NodePort" | "LoadBalancer" | "ExternalName"
	Headless  bool   // spec.clusterIP == "None"
	Ports     []ServicePort
}

// ServicePort is one declared port on a Service.
type ServicePort struct {
	Name     string // optional, e.g. "http", "https", "metrics"
	Port     int
	Protocol string // "TCP" | "UDP" | "SCTP" (kube layer)
}

// SnapshotItem is the wire shape sent to the Console; mirrors
// transport.DiscoverySnapshotItem but lives here so the package has
// no transport dep.
//
// Path is meaningful for ingresses, empty for services.
// Port is meaningful for services, zero for ingresses.
// Protocol is one of "http", "https", "tcp", "udp" (the agent's
// classification, not the kube layer's).
type SnapshotItem struct {
	Kind         string // "ingress" | "service"
	Namespace    string
	ResourceName string
	Host         string
	Path         string
	Port         int
	Protocol     string
}
