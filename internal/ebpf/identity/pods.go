package identity

import (
	"context"
	"sync"
	"time"
)

// PodRef names a pod.
type PodRef struct{ Name, Namespace string }

// PodResolver maps pod UIDs to names. It reloads the node's pod list on a
// miss, at most once per minRefresh, so a burst of processes in a new pod
// costs one apiserver call. A nil list func (not on Kubernetes) resolves
// nothing.
type PodResolver struct {
	list       func(context.Context) (map[string]PodRef, error)
	minRefresh time.Duration

	mu     sync.Mutex
	pods   map[string]PodRef
	loaded time.Time
}

func NewPodResolver(list func(context.Context) (map[string]PodRef, error), minRefresh time.Duration) *PodResolver {
	return &PodResolver{list: list, minRefresh: minRefresh}
}

func (r *PodResolver) Resolve(ctx context.Context, uid string) (PodRef, bool) {
	if r == nil || r.list == nil || uid == "" {
		return PodRef{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.pods[uid]; ok {
		return p, true
	}
	if time.Since(r.loaded) < r.minRefresh {
		return PodRef{}, false
	}
	r.loaded = time.Now()
	pods, err := r.list(ctx)
	if err != nil {
		return PodRef{}, false
	}
	r.pods = pods
	p, ok := pods[uid]
	return p, ok
}
