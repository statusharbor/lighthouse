package discovery

import (
	"context"
	"errors"
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

	mu         sync.Mutex
	ingresses  map[string]*Ingress  // key = namespace/name
	services   map[string]*Service  // key = namespace/name
	httproutes map[string]*HTTPRoute // key = namespace/name; nil-map ⇒ Gateway-API CRD not installed
	lastSent   []SnapshotItem
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
		// httproutes intentionally nil: probeHTTPRouteCRD flips it to
		// an empty map on success. Nil = "no Gateway-API CRDs here,
		// don't spin up the HTTPRoute watch loops" — see Run.
		httproutes: nil,
	}, nil
}

// Run blocks until ctx is cancelled. Spawns one watch goroutine per
// (kind × namespace) plus a debounced sender goroutine. The HTTPRoute
// watch is gated on a startup-time CRD probe so Ingress-only clusters
// pay no kube-API cost for it.
func (w *Watcher) Run(ctx context.Context) {
	dirty := make(chan struct{}, 1)
	notify := func() {
		select {
		case dirty <- struct{}{}:
		default:
		}
	}

	httprouteEnabled := w.probeHTTPRouteCRD(ctx)

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
		if httprouteEnabled {
			wg.Add(1)
			go func(ns string) {
				defer wg.Done()
				w.httprouteWatchLoop(ctx, ns, notify)
			}(nsArg)
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		w.senderLoop(ctx, dirty)
	}()

	wg.Wait()
}

// probeHTTPRouteCRD checks whether gateway.networking.k8s.io/v1
// HTTPRoute is installed on this cluster. A 404 (CRD missing) flips the
// HTTPRoute watch off cleanly; any other error logs Warn and returns
// false so a transient apiserver hiccup at startup doesn't permanently
// disable the watch. On success, the httproutes cache is initialised to
// an empty map so the snapshot builder treats "no items" distinctly
// from "feature disabled".
func (w *Watcher) probeHTTPRouteCRD(ctx context.Context) bool {
	// A single zero-namespace list at startup. We don't seed the cache
	// from it - the per-namespace listHTTPRoutes in the watch loop
	// will do that under the same lock the rest of replaceX uses.
	_, err := w.kube.listHTTPRoutes(ctx, "")
	if err == nil {
		w.mu.Lock()
		w.httproutes = map[string]*HTTPRoute{}
		w.mu.Unlock()
		slog.Info("discovery: Gateway-API HTTPRoute watch enabled")
		return true
	}
	if errors.Is(err, errHTTPRouteCRDMissing) {
		slog.Info("discovery: Gateway-API CRDs not installed; HTTPRoute watch disabled")
		return false
	}
	slog.Warn("discovery: HTTPRoute CRD probe failed; watch disabled this run",
		"error", err)
	return false
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

// httprouteWatchLoop mirrors ingressWatchLoop / serviceWatchLoop. If
// the CRD goes away mid-run (cluster admin uninstalls Gateway API), the
// loop exits cleanly on the next watchHTTPRoutes call instead of
// retry-storming the apiserver.
func (w *Watcher) httprouteWatchLoop(ctx context.Context, ns string, notify func()) {
	attempt := 0
	for ctx.Err() == nil {
		list, err := w.kube.listHTTPRoutes(ctx, ns)
		if errors.Is(err, errHTTPRouteCRDMissing) {
			slog.Info("kube httproute CRD removed; stopping watch loop", "namespace", ns)
			return
		}
		if err != nil {
			slog.Warn("kube list httproutes failed; will retry", "namespace", ns, "error", err)
			attempt++
			minBackoff(ctx, attempt)
			continue
		}
		attempt = 0
		w.replaceHTTPRoutes(ns, list.Items)
		notify()

		if err := w.kube.watchHTTPRoutes(ctx, ns, list.Metadata.ResourceVersion, notify); err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, errHTTPRouteCRDMissing) {
				slog.Info("kube httproute CRD removed; stopping watch loop", "namespace", ns)
				return
			}
			slog.Debug("kube httproute watch ended; relisting", "namespace", ns, "error", err)
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

// replaceHTTPRoutes swaps the cached HTTPRoute state for one namespace.
// Always operates on a non-nil map because probeHTTPRouteCRD seeded it
// before any watch loop started.
func (w *Watcher) replaceHTTPRoutes(ns string, items []httprouteJSON) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.httproutes == nil {
		// Defensive: a CRD that flickered in-and-out across runs
		// could in principle land us here. Treat as a no-op rather
		// than nil-deref.
		w.httproutes = map[string]*HTTPRoute{}
	}
	if ns == "" {
		w.httproutes = make(map[string]*HTTPRoute, len(items))
	} else {
		for k, v := range w.httproutes {
			if v.Namespace == ns {
				delete(w.httproutes, k)
			}
		}
	}
	for _, it := range items {
		rt := fromKubeHTTPRoute(it)
		w.httproutes[rt.Namespace+"/"+rt.Name] = rt
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
		snap := BuildSnapshot(w.ingresses, w.services, w.httproutes)
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
