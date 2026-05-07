package discovery

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Watcher owns the kube-API watch loop and the snapshot push cadence.
// Lifecycle:
//   1. List+watch each configured namespace (or all-namespaces).
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

	// SendFunc is invoked with each fresh snapshot. It must not block
	// for long — a 30s context is provided by Run. Errors are logged
	// and ignored; the next event will retry.
	SendFunc func(ctx context.Context, items []SnapshotItem) error

	mu         sync.Mutex
	state      map[string]*Ingress // key = namespace/name
	lastSent   []SnapshotItem
}

// NewWatcher constructs a Watcher when running in-cluster. Returns
// (nil, nil) when not in a cluster — the caller treats that as
// "discovery disabled".
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
		state:      map[string]*Ingress{},
	}, nil
}

// Run blocks until ctx is cancelled. Spawns one watch goroutine per
// namespace plus a debounced sender goroutine.
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
		wg.Add(1)
		go func(ns string) {
			defer wg.Done()
			w.watchLoop(ctx, ns, notify)
		}(nsArg)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		w.senderLoop(ctx, dirty)
	}()

	wg.Wait()
}

// watchLoop runs the list+watch+relist cycle for one namespace.
func (w *Watcher) watchLoop(ctx context.Context, ns string, notify func()) {
	attempt := 0
	for ctx.Err() == nil {
		list, err := w.kube.listIngresses(ctx, ns)
		if err != nil {
			slog.Warn("kube list failed; will retry", "namespace", ns, "error", err)
			attempt++
			minBackoff(ctx, attempt)
			continue
		}
		attempt = 0
		w.replaceNamespace(ns, list.Items)
		notify()

		if err := w.kube.watchIngresses(ctx, ns, list.Metadata.ResourceVersion, notify); err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Debug("kube watch ended; relisting", "namespace", ns, "error", err)
		}
	}
}

// replaceNamespace swaps the cached state for one namespace with the
// freshly-listed set. ns="" means all-namespaces; in that case we
// clear the whole state and rebuild.
func (w *Watcher) replaceNamespace(ns string, items []ingressJSON) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ns == "" {
		w.state = make(map[string]*Ingress, len(items))
	} else {
		for k, v := range w.state {
			if v.Namespace == ns {
				delete(w.state, k)
			}
		}
	}
	for _, it := range items {
		ing := fromKubeIngress(it)
		w.state[ing.Namespace+"/"+ing.Name] = ing
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
		// Debounce: keep collecting events for `debounce` window.
		t := time.NewTimer(w.debounce)
		drain := true
		for drain {
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-dirty:
				// reset timer
				if !t.Stop() {
					<-t.C
				}
				t.Reset(w.debounce)
			case <-t.C:
				drain = false
			}
		}

		w.mu.Lock()
		snap := BuildSnapshot(w.state)
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
			// Force the next event to retry by clearing lastSent.
			w.mu.Lock()
			w.lastSent = nil
			w.mu.Unlock()
		} else {
			slog.Debug("discovery snapshot sent", "items", len(snap))
		}
		cancel()
	}
}
