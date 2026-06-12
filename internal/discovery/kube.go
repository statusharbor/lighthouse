package discovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// kubeClient is a minimal HTTPS client for the Kubernetes API. It uses
// the in-cluster service account when available — pulling token + CA
// from the standard projection paths.
//
// We deliberately avoid client-go to keep the agent binary small.
// Discovery only needs networking.k8s.io/v1/Ingress list+watch.
type kubeClient struct {
	apiServer string
	token     string
	httpc     *http.Client
}

const (
	tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	caPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// IsKubernetes returns true when the agent is running inside a
// Kubernetes pod. Cheap, no I/O: just checks for the
// KUBERNETES_SERVICE_HOST env var that kubelet injects into every pod.
//
// Note this is a lower bar than "can we talk to the apiserver" —
// inClusterClient (below) also requires the ServiceAccount token file
// and a valid CA bundle. The registration handler only needs to know
// "are we in a pod" to decide whether to flip the Lighthouse's
// allow_multi_instance flag, not whether discovery itself will work,
// so the env-var probe is the right primitive here.
func IsKubernetes() bool {
	return os.Getenv("KUBERNETES_SERVICE_HOST") != ""
}

// inClusterClient builds a client from the standard service-account
// projection. Returns (nil, nil) when not running in a cluster (the
// agent treats this as "discovery silently disabled").
func inClusterClient() (*kubeClient, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, nil
	}
	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, nil
	}
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, errors.New("invalid kube CA bundle")
	}
	return &kubeClient{
		apiServer: fmt.Sprintf("https://%s:%s", host, port),
		token:     strings.TrimSpace(string(tokenBytes)),
		httpc: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool},
			},
		},
	}, nil
}

// listIngresses returns the current set of ingresses for one namespace
// (or all namespaces when ns == ""). Returns the resourceVersion the
// watch should resume from.
type ingressList struct {
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Items []ingressJSON `json:"items"`
}

type ingressJSON struct {
	Metadata struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		TLS []struct {
			Hosts []string `json:"hosts"`
		} `json:"tls"`
		Rules []struct {
			Host string `json:"host"`
			HTTP struct {
				Paths []struct {
					Path     string `json:"path"`
					PathType string `json:"pathType"`
				} `json:"paths"`
			} `json:"http"`
		} `json:"rules"`
	} `json:"spec"`
}

func (k *kubeClient) listURL(ns string) string {
	if ns == "" {
		return k.apiServer + "/apis/networking.k8s.io/v1/ingresses"
	}
	return fmt.Sprintf("%s/apis/networking.k8s.io/v1/namespaces/%s/ingresses",
		k.apiServer, url.PathEscape(ns))
}

func (k *kubeClient) listIngresses(ctx context.Context, ns string) (*ingressList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.listURL(ns), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")
	resp, err := k.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list ingresses: %s — %s", resp.Status, string(body))
	}
	var out ingressList
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode list: %w", err)
	}
	return &out, nil
}

// watchEvent is the chunked-streaming envelope from the kube API
// watch endpoint. We only inspect Type and Object.metadata to know
// which key is affected; the actual fields come from a fresh list
// after a debounce window.
type watchEvent struct {
	Type   string      `json:"type"`
	Object ingressJSON `json:"object"`
}

// watchIngresses streams events from resourceVersion=rv until the
// connection drops or ctx is cancelled. onEvent is invoked for each
// ADDED/MODIFIED/DELETED; the caller debounces and re-snapshots.
func (k *kubeClient) watchIngresses(ctx context.Context, ns, rv string, onEvent func()) error {
	u := k.listURL(ns) + "?watch=true&resourceVersion=" + url.QueryEscape(rv)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")
	// No client-side timeout: kube returns 410 GONE when rv expires,
	// we treat any clean close as a relist trigger.
	hc := *k.httpc
	hc.Timeout = 0
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusGone {
		return errResourceVersionGone
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("watch: %s", resp.Status)
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var ev watchEvent
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		switch ev.Type {
		case "ADDED", "MODIFIED", "DELETED":
			onEvent()
		case "ERROR":
			return errResourceVersionGone
		}
	}
}

var errResourceVersionGone = errors.New("kube watch: resource version expired, relist")

// fromKubeIngress projects the kube JSON shape onto the local Ingress.
func fromKubeIngress(ki ingressJSON) *Ingress {
	out := &Ingress{
		Namespace: ki.Metadata.Namespace,
		Name:      ki.Metadata.Name,
		TLSHosts:  map[string]bool{},
	}
	for _, t := range ki.Spec.TLS {
		for _, h := range t.Hosts {
			out.TLSHosts[h] = true
		}
	}
	for _, r := range ki.Spec.Rules {
		rule := IngressRule{Host: r.Host}
		for _, p := range r.HTTP.Paths {
			rule.Paths = append(rule.Paths, IngressPath{Path: p.Path, Type: p.PathType})
		}
		out.Rules = append(out.Rules, rule)
	}
	return out
}

// ---- Services ----------------------------------------------------------

type serviceList struct {
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Items []serviceJSON `json:"items"`
}

type serviceJSON struct {
	Metadata struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Type      string `json:"type"`
		ClusterIP string `json:"clusterIP"`
		Ports     []struct {
			Name     string `json:"name"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		} `json:"ports"`
	} `json:"spec"`
}

func (k *kubeClient) serviceListURL(ns string) string {
	if ns == "" {
		return k.apiServer + "/api/v1/services"
	}
	return fmt.Sprintf("%s/api/v1/namespaces/%s/services",
		k.apiServer, url.PathEscape(ns))
}

func (k *kubeClient) listServices(ctx context.Context, ns string) (*serviceList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.serviceListURL(ns), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")
	resp, err := k.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list services: %s — %s", resp.Status, string(body))
	}
	var out serviceList
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode list: %w", err)
	}
	return &out, nil
}

type serviceWatchEvent struct {
	Type   string      `json:"type"`
	Object serviceJSON `json:"object"`
}

// watchServices mirrors watchIngresses but for the core/v1 services
// endpoint.
func (k *kubeClient) watchServices(ctx context.Context, ns, rv string, onEvent func()) error {
	u := k.serviceListURL(ns) + "?watch=true&resourceVersion=" + url.QueryEscape(rv)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")
	hc := *k.httpc
	hc.Timeout = 0
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusGone {
		return errResourceVersionGone
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("watch: %s", resp.Status)
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var ev serviceWatchEvent
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		switch ev.Type {
		case "ADDED", "MODIFIED", "DELETED":
			onEvent()
		case "ERROR":
			return errResourceVersionGone
		}
	}
}

// fromKubeService projects the kube JSON onto a local Service.
func fromKubeService(sj serviceJSON) *Service {
	out := &Service{
		Namespace: sj.Metadata.Namespace,
		Name:      sj.Metadata.Name,
		Type:      sj.Spec.Type,
		Headless:  sj.Spec.ClusterIP == "None",
	}
	for _, p := range sj.Spec.Ports {
		proto := p.Protocol
		if proto == "" {
			proto = "TCP" // kube default
		}
		out.Ports = append(out.Ports, ServicePort{
			Name:     p.Name,
			Port:     p.Port,
			Protocol: proto,
		})
	}
	return out
}

// ---- Common ------------------------------------------------------------

// minBackoff sleeps a small amount on watch failure, scaling up to
// avoid hot-looping against a broken kube API. Returns immediately
// when ctx is cancelled.
func minBackoff(ctx context.Context, attempt int) {
	d := time.Second
	for i := 0; i < attempt && d < 30*time.Second; i++ {
		d *= 2
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
