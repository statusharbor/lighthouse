package k8sstats

import (
	"context"
	"net/url"

	"github.com/statusharbor/lighthouse/internal/ebpf/identity"
)

// NodePodLister returns a function listing the pods scheduled on
// nodeName, keyed by pod UID, for the eBPF identity cache. Nil outside a
// cluster or when nodeName is unknown. Needs list on pods for the agent's
// service account.
func NodePodLister(nodeName string) (func(context.Context) (map[string]identity.PodRef, error), error) {
	k, err := inClusterClient()
	if k == nil || err != nil || nodeName == "" {
		return nil, err
	}
	path := "/api/v1/pods?fieldSelector=" + url.QueryEscape("spec.nodeName="+nodeName)
	return func(ctx context.Context) (map[string]identity.PodRef, error) {
		var list struct {
			Items []struct {
				Metadata struct {
					UID       string `json:"uid"`
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
			} `json:"items"`
		}
		if err := k.get(ctx, path, &list); err != nil {
			return nil, err
		}
		out := make(map[string]identity.PodRef, len(list.Items))
		for _, p := range list.Items {
			out[p.Metadata.UID] = identity.PodRef{Name: p.Metadata.Name, Namespace: p.Metadata.Namespace}
		}
		return out, nil
	}, nil
}
