//go:build linux && (386 || amd64 || arm64)

package requests

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/statusharbor/lighthouse/internal/ebpf"
	"github.com/statusharbor/lighthouse/internal/ebpf/identity"
	"github.com/statusharbor/lighthouse/internal/traces"
)

// defaultPort is where a supervised OBI serves its Prometheus endpoint.
const defaultPort = "19400"

// Collector reports passive request metrics from OBI. With Path set it
// starts OBI and restarts it through the manager when it exits; with only
// MetricsURL it reads an OBI sidecar (the Kubernetes packaging). Either
// way OBI's crash or absence never touches the other collectors; a scrape
// gap is no data, never zero traffic (criterion 6).
type Collector struct {
	Identity   *identity.Collector
	Path       string
	MetricsURL string
	Ports      string
	Checks     func() []CheckTarget // Lighthouse's own checks on this host
	Interval   time.Duration
	// Traces receives OBI's spans on loopback (status-harbor
	// docs/eBPF/11-traces.md); nil turns trace export off.
	Traces *traces.Pipeline
}

func New(ident *identity.Collector, path, metricsURL, ports string) *Collector {
	return &Collector{Identity: ident, Path: path, MetricsURL: metricsURL, Ports: ports, Interval: 15 * time.Second}
}

func (*Collector) Name() string { return "requests" }

func (c *Collector) Requirements() ebpf.Requirements {
	return ebpf.Requirements{Features: []ebpf.Feature{{Name: "OBI binary or sidecar", Probe: func() error {
		switch {
		case c.Path != "":
			_, err := os.Stat(c.Path)
			return err
		case c.MetricsURL != "":
			return nil
		}
		return errors.New("no OBI configured (agent.obi.path or agent.obi.metrics_url)")
	}}}}
}

// service resolves OBI's instance label ("<host>:<pid>") to the plan 03
// service identity of that process, with its port (L7-U-P6).
func (c *Collector) service(ctx context.Context) func(instance, job, port string) string {
	return func(instance, job, port string) string {
		_, pidStr, _ := strings.Cut(instance, ":")
		pid, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil || c.Identity == nil {
			return withPort("comm:"+job, port)
		}
		return withPort(identity.SourceID(c.Identity.Lookup(ctx, identity.Key{PID: uint32(pid)}), job), port)
	}
}

// TraceIdentity resolves OBI's service.instance.id ("host:pid") to the
// plan 03 identity without a port, as the service map names nodes.
func (c *Collector) TraceIdentity(ctx context.Context, instance, serviceName string) string {
	_, pidStr, _ := strings.Cut(instance, ":")
	pid, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil || c.Identity == nil {
		return "comm:" + serviceName
	}
	return identity.SourceID(c.Identity.Lookup(ctx, identity.Key{PID: uint32(pid)}), serviceName)
}

// obiEnv is a supervised OBI's environment. Context propagation is always
// disabled: Lighthouse never writes into customers' traffic (TRC-U-F6).
// The trace export points at the loopback receiver only while traces are
// on.
func obiEnv(base []string, ports string, p *traces.Pipeline) []string {
	env := append(base,
		"OTEL_EBPF_PROMETHEUS_PORT="+defaultPort,
		"OTEL_EBPF_OPEN_PORT="+ports,
		"OTEL_EBPF_LOG_LEVEL=WARN",
		"OTEL_EBPF_BPF_CONTEXT_PROPAGATION=disabled",
	)
	if p.Enabled() {
		env = append(env,
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://"+traces.ReceiverAddr+"/v1/traces",
			"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/protobuf",
		)
		if p.Token != "" {
			env = append(env, "OTEL_EXPORTER_OTLP_TRACES_HEADERS="+traces.TokenHeader+"="+p.Token)
		}
	}
	return env
}

// OBI pins one BPF map (traces_ctx_v1, its shared trace context) under
// OTEL_EBPF_BPF_FS_PATH and leaves it after it exits. Each agent gives its
// OBI a private directory there and deletes it when OBI stops, so nothing
// stays loaded. Without bpffs at bpfFS the variable is left out: OBI then
// keeps the map private by itself (a path off bpffs would fail it).
const (
	bpfFS     = "/sys/fs/bpf"
	pinPrefix = "statusharbor-obi-"
)

func onBPFFS(path string) bool {
	var st unix.Statfs_t
	// Type is int32 on 32-bit platforms, where the magic overflows it.
	return unix.Statfs(path, &st) == nil && uint32(st.Type) == unix.BPF_FS_MAGIC
}

// sweepPins removes pin directories of agents that are gone (a crash or
// kill -9 skips the cleanup on stop).
// ponytail: keyed by PID, so a reused PID keeps a stale directory (one
// small map) until that process exits too.
func sweepPins(root string, alive func(pid int) bool) {
	dirs, _ := filepath.Glob(filepath.Join(root, pinPrefix+"*"))
	for _, d := range dirs {
		pid, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(d), pinPrefix))
		if err == nil && !alive(pid) {
			_ = os.RemoveAll(d)
		}
	}
}

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// startOBI runs a supervised OBI until stop is called or it exits.
func (c *Collector) startOBI(ctx context.Context) (stop func(), exited chan error, err error) {
	ports := c.Ports
	if ports == "" {
		ports = "1-65535"
	}
	ctx, cancel := context.WithCancel(ctx)
	// ponytail: OBI inherits the agent's user and capabilities. The
	// Kubernetes sidecar packaging gives it its own instead.
	cmd := exec.CommandContext(ctx, c.Path)
	cmd.Env = obiEnv(os.Environ(), ports, c.Traces)
	pins := ""
	if onBPFFS(bpfFS) {
		sweepPins(bpfFS, processAlive)
		pins = filepath.Join(bpfFS, pinPrefix+strconv.Itoa(os.Getpid()))
		cmd.Env = append(cmd.Env, "OTEL_EBPF_BPF_FS_PATH="+pins)
	}
	// OBI logs at WARN: its own failures (an export it cannot deliver,
	// a process it cannot instrument) belong in the agent's log.
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, nil, fmt.Errorf("start OBI: %w", err)
	}
	exited = make(chan error, 1)
	done := make(chan struct{})
	go func() {
		exited <- cmd.Wait()
		if pins != "" {
			_ = os.RemoveAll(pins)
		}
		close(done)
	}()
	return func() { cancel(); <-done }, exited, nil
}

func (c *Collector) Run(ctx context.Context, sink ebpf.Sink) error {
	if c.Traces != nil {
		ln, err := net.Listen("tcp", traces.ReceiverAddr)
		if err != nil {
			return fmt.Errorf("traces receiver: %w", err)
		}
		srv := &http.Server{Handler: c.Traces, ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = srv.Serve(ln) }()
		defer func() { _ = srv.Close() }()
	}
	url := c.MetricsURL
	var exited chan error
	var restart func() error
	tracing := c.Traces.Enabled()
	if c.Path != "" {
		url = "http://127.0.0.1:" + defaultPort + "/metrics"
		stop, ex, err := c.startOBI(ctx)
		if err != nil {
			return err
		}
		exited = ex
		defer func() { stop() }()
		// Restart OBI here, not through the manager, when traces are
		// turned on or off: a flip is not a failure.
		restart = func() error {
			stop()
			s, ex, err := c.startOBI(ctx)
			if err != nil {
				return err
			}
			stop, exited, tracing = s, ex, c.Traces.Enabled()
			return nil
		}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	var prev map[histKey]*hist
	var prevAt time.Time
	failures := 0
	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-exited:
			return fmt.Errorf("OBI exited: %w", err)
		case now := <-t.C:
			if restart != nil && c.Traces.Enabled() != tracing {
				if err := restart(); err != nil {
					return err
				}
				prev = nil // a new OBI starts its counters at zero
			}
			snap, err := c.scrape(ctx, client, url)
			if err != nil {
				failures++
				if failures == 3 {
					if d, ok := sink.(ebpf.Degrader); ok {
						d.Degrade("OBI not reachable: " + err.Error())
					}
				}
				continue
			}
			failures = 0
			if prev != nil {
				for _, s := range convert(delta(prev, snap), now.Sub(prevAt)) {
					sink.Gauge(s.Name, s.Value, s.Labels)
				}
			}
			prev, prevAt = snap, now
		}
	}
}

func (c *Collector) scrape(ctx context.Context, client *http.Client, url string) (map[histKey]*hist, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	var checks []CheckTarget
	if c.Checks != nil {
		checks = c.Checks()
	}
	return snapshot(parseText(resp.Body), c.service(ctx), checks), nil
}
