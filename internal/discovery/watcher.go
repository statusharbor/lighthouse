package discovery

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Watcher owns the kube-API watch loops (one per resource kind ×
// namespace) and the snapshot push cadence.
//
// Lifecycle:
//   1. List+watch each (kind × namespace) pair.
//   2. On every watch event, set a dirty flag.
//   3. A debounced ticker collects bursts and calls SendFunc with the
//      current snapshot. No periodic resync — the watch's own
//      relist-on-disconnect is the safety net.
//   4. On watch error or RV expiration, relist and continue.
//
// Outside a Kubernetes cluster, NewWatcher returns nil and Run is a
// no-op — discovery silently disables itself.
type Watcher struct {
	kube       *kubeClient
	namespaces []string // empty / ["*"] ⇒ all namespaces
	debounce   time.Duration

	// SendFunc is invoked with each fresh snapshot.
	SendFunc func(ctx context.Context, items []SnapshotItem) error

	mu        sync.Mutex
	ingresses map[string]*Ingress // key = namespace/name
	services  map[string]*Service // key = namespace/name
	lastSent  []SnapshotItem
}

// NewWatcher constructs a Watcher when running in-cluster. Returns
// (nil, nil) when not in a cluster.
func NewWatcher(namespaces []string) (*Watcher, error) {
	k, err := inClusterClient()
	if err != nil {
		return nil, err
	}
	if k == nil {
		return nil, nil
	}
	if len(namespaces) == 0 {
		namespaces = []string{"*"}
	}
	return &Watcher{
		kube:       k,
		namespaces: namespaces,
		debounce:   2 * time.Second,
		ingresses:  map[string]*Ingress{},
		services:   map[string]*Service{},
	}, nil
}

// Run blocks until ctx is cancelled. Spawns one watch goroutine per
// (kind × namespace) plus a debounced sender goroutine.
func (w *Watcher) Run(ctx context.Context) {
	dirty := make(chan struct{}, 1)
	notify := func() {
		select {
		case dirty <- struct{}{}:
		default:
		}
	}

	var wg sync.WaitGroup
	for _, ns := range w.namespaces {
		nsArg := ""
		if ns != "*" {
			nsArg = ns
		}
		wg.Add(2)
		go func(ns string) {
			defer wg.Done()
			w.ingressWatchLoop(ctx, ns, notify)
		}(nsArg)
		go func(ns string) {
			defer wg.Done()
			w.serviceWatchLoop(ctx, ns, notify)
		}(nsArg)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		w.senderLoop(ctx, dirty)
	}()

	wg.Wait()
}

func (w *Watcher) ingressWatchLoop(ctx context.Context, ns string, notify func()) {
	attempt := 0
	for ctx.Err() == nil {
		list, err := w.kube.listIngresses(ctx, ns)
		if err != nil {
			slog.Warn("kube list ingresses failed; will retry", "namespace", ns, "error", err)
			attempt++
			minBackoff(ctx, attempt)
			continue
		}
		attempt = 0
		w.replaceIngresses(ns, list.Items)
		notify()

		if err := w.kube.watchIngresses(ctx, ns, list.Metadata.ResourceVersion, notify); err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Debug("kube ingress watch ended; relisting", "namespace", ns, "error", err)
		}
	}
}

func (w *Watcher) serviceWatchLoop(ctx context.Context, ns string, notify func()) {
	attempt := 0
	for ctx.Err() == nil {
		list, err := w.kube.listServices(ctx, ns)
		if err != nil {
			slog.Warn("kube list services failed; will retry", "namespace", ns, "error", err)
			attempt++
			minBackoff(ctx, attempt)
			continue
		}
		attempt = 0
		w.replaceServices(ns, list.Items)
		notify()

		if err := w.kube.watchServices(ctx, ns, list.Metadata.ResourceVersion, notify); err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Debug("kube service watch ended; relisting", "namespace", ns, "error", err)
		}
	}
}

// replaceIngresses swaps the cached Ingress state for one namespace
// (or all-namespaces when ns == "") with the freshly-listed set.
func (w *Watcher) replaceIngresses(ns string, items []ingressJSON) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ns == "" {
		w.ingresses = make(map[string]*Ingress, len(items))
	} else {
		for k, v := range w.ingresses {
			if v.Namespace == ns {
				delete(w.ingresses, k)
			}
		}
	}
	for _, it := range items {
		ing := fromKubeIngress(it)
		w.ingresses[ing.Namespace+"/"+ing.Name] = ing
	}
}

// replaceServices swaps the cached Service state for one namespace.
func (w *Watcher) replaceServices(ns string, items []serviceJSON) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ns == "" {
		w.services = make(map[string]*Service, len(items))
	} else {
		for k, v := range w.services {
			if v.Namespace == ns {
				delete(w.services, k)
			}
		}
	}
	for _, it := range items {
		svc := fromKubeService(it)
		w.services[svc.Namespace+"/"+svc.Name] = svc
	}
}

// senderLoop debounces dirty notifications and POSTs snapshots. Skips
// no-op POSTs by comparing against the last sent payload.
func (w *Watcher) senderLoop(ctx context.Context, dirty <-chan struct{}) {
	if w.SendFunc == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-dirty:
		}
		t := time.NewTimer(w.debounce)
		drain := true
		for drain {
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-dirty:
				if !t.Stop() {
					<-t.C
				}
				t.Reset(w.debounce)
			case <-t.C:
				drain = false
			}
		}

		w.mu.Lock()
		snap := BuildSnapshot(w.ingresses, w.services)
		same := SnapshotsEqual(snap, w.lastSent)
		if !same {
			w.lastSent = snap
		}
		w.mu.Unlock()

		if same {
			continue
		}
		sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := w.SendFunc(sendCtx, snap); err != nil {
			slog.Warn("discovery send failed; will retry on next change",
				"items", len(snap), "error", err)
			w.mu.Lock()
			w.lastSent = nil
			w.mu.Unlock()
		} else {
			slog.Info("discovery snapshot sent", "items", len(snap))
		}
		cancel()
	}
}
