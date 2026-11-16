package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// AddressEntry maps one cluster IP to what it belongs to, so the Console
// can resolve dependency-edge destinations (docs/eBPF/03-service-discovery.md,
// "Kubernetes"). With kube-proxy a connection shows the Service's
// ClusterIP; with socket-level load balancing (Cilium) it shows a pod IP.
// Both resolve to the same Service (DSC-U-P6).
type AddressEntry struct {
	IP        string `json:"ip"`
	Namespace string `json:"namespace"`
	Service   string `json:"service,omitempty"`  // "" for a pod no Service selects
	Workload  string `json:"workload,omitempty"` // "" for a Service's ClusterIP
}

// maxAddressEntries bounds one snapshot; bigger clusters are truncated.
const maxAddressEntries = 10000

type podList struct {
	Items []podJSON `json:"items"`
}

type podJSON struct {
	Metadata struct {
		Namespace       string            `json:"namespace"`
		Name            string            `json:"name"`
		Labels          map[string]string `json:"labels"`
		OwnerReferences []struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		HostNetwork bool `json:"hostNetwork"`
	} `json:"spec"`
	Status struct {
		PodIPs []struct {
			IP string `json:"ip"`
		} `json:"podIPs"`
	} `json:"status"`
}

var replicaSetHash = regexp.MustCompile(`-[bcdfghjklmnpqrstvwxz2456789]{6,10}$`)

// podWorkload names the workload that owns a pod: the Deployment behind a
// ReplicaSet, or the StatefulSet, DaemonSet or Job itself.
func podWorkload(p podJSON) string {
	if len(p.Metadata.OwnerReferences) == 0 {
		return p.Metadata.Name
	}
	o := p.Metadata.OwnerReferences[0]
	if o.Kind == "ReplicaSet" {
		return replicaSetHash.ReplaceAllString(o.Name, "")
	}
	return o.Name
}

func selects(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// BuildAddressMap returns one entry per Service ClusterIP and per pod IP,
// sorted by IP. Pods on the host network share the node's address and are
// skipped; headless Services have no ClusterIP.
func BuildAddressMap(services []serviceJSON, pods []podJSON) []AddressEntry {
	var out []AddressEntry
	for _, s := range services {
		ips := s.Spec.ClusterIPs
		if len(ips) == 0 && s.Spec.ClusterIP != "" {
			ips = []string{s.Spec.ClusterIP}
		}
		for _, ip := range ips {
			if ip != "" && ip != "None" {
				out = append(out, AddressEntry{IP: ip, Namespace: s.Metadata.Namespace, Service: s.Metadata.Name})
			}
		}
	}
	for _, p := range pods {
		if p.Spec.HostNetwork {
			continue
		}
		svc := ""
		for _, s := range services {
			if s.Metadata.Namespace == p.Metadata.Namespace && selects(s.Spec.Selector, p.Metadata.Labels) {
				svc = s.Metadata.Name
				break
			}
		}
		for _, ip := range p.Status.PodIPs {
			if ip.IP != "" {
				out = append(out, AddressEntry{IP: ip.IP, Namespace: p.Metadata.Namespace, Service: svc, Workload: podWorkload(p)})
			}
		}
	}
	slices.SortFunc(out, func(a, b AddressEntry) int { return strings.Compare(a.IP, b.IP) })
	if len(out) > maxAddressEntries {
		out = out[:maxAddressEntries]
	}
	return out
}

func (k *kubeClient) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")
	resp, err := k.httpc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("GET %s: %s - %s", u, resp.Status, string(body))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// RunAddressMap lists Services and pods every interval and sends the
// address map when it changed. Namespaces empty means the whole cluster.
// Listing pods needs the pods list permission in the discovery role; on a
// 403 the map carries Services only.
func RunAddressMap(ctx context.Context, namespaces []string, interval time.Duration, send func(context.Context, []AddressEntry) error) {
	k, err := inClusterClient()
	if err != nil || k == nil {
		return
	}
	if len(namespaces) == 0 {
		namespaces = []string{""}
	}
	var last []AddressEntry
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		var services []serviceJSON
		var pods []podJSON
		for _, ns := range namespaces {
			var sl serviceList
			if err := k.getJSON(ctx, k.serviceListURL(ns), &sl); err != nil {
				slog.Warn("k8s address map: list services failed", "namespace", ns, "error", err)
				continue
			}
			services = append(services, sl.Items...)
			podsURL := k.apiServer + "/api/v1/pods"
			if ns != "" {
				podsURL = fmt.Sprintf("%s/api/v1/namespaces/%s/pods", k.apiServer, url.PathEscape(ns))
			}
			var pl podList
			if err := k.getJSON(ctx, podsURL, &pl); err != nil {
				slog.Warn("k8s address map: list pods failed", "namespace", ns, "error", err)
			}
			pods = append(pods, pl.Items...)
		}
		if m := BuildAddressMap(services, pods); !slices.Equal(m, last) {
			if err := send(ctx, m); err != nil {
				slog.Warn("k8s address map: send failed", "error", err)
			} else {
				last = m
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
