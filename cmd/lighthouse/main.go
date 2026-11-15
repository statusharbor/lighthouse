// Lighthouse — private network monitoring agent for Status Harbor.
//
// Single static binary: load config, register, initial-sync, run heartbeat
// + check scheduler in parallel, exit cleanly on SIGTERM. Console URL is
// hardcoded; agent learns its identity from the bound scoped token.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/statusharbor/lighthouse/internal/agent"
	"github.com/statusharbor/lighthouse/internal/agent/database"
	"github.com/statusharbor/lighthouse/internal/agent/k8sstats"
	"github.com/statusharbor/lighthouse/internal/discovery"
	"github.com/statusharbor/lighthouse/internal/traces"
	"github.com/statusharbor/lighthouse/internal/transport"
)

var (
	configPath = flag.String("config", "lighthouse.yaml", "path to lighthouse.yaml")
)

func main() {
	flag.Parse()
	if *dryRun && os.Getenv(agent.EnvToken) == "" {
		// The dry run never connects, so it needs no token.
		_ = os.Setenv(agent.EnvToken, "dry-run")
	}

	cfg, err := agent.LoadFile(*configPath)
	if err != nil {
		slog.Error("config load failed", "path", *configPath, "error", err)
		os.Exit(2)
	}
	configureLogging(cfg.Agent.LogLevel)
	if *dryRun {
		if err := runDryRun(cfg); err != nil {
			slog.Error("dry run failed", "error", err)
			os.Exit(1)
		}
		return
	}

	hostname, _ := os.Hostname()
	slog.Info("lighthouse starting",
		"version", agent.AgentVersion,
		"hostname", hostname,
		"data_dir", cfg.Agent.DataDir,
	)

	// Stable per-install UUID for the Console's single-active-instance
	// claim. Empty string on failure (read-only data dir, etc.) — the
	// transport treats that as "don't participate" so older Consoles +
	// degraded installs keep running. Logged at Warn so operators can
	// see the agent isn't asserting an identity.
	instanceID, err := agent.LoadOrCreateInstanceID(cfg.Agent.DataDir)
	if err != nil {
		slog.Warn("instance id unavailable — running without single-active-instance claim",
			"data_dir", cfg.Agent.DataDir, "error", err)
	} else {
		slog.Info("instance id loaded", "instance_id", instanceID)
	}

	// Per-install NaCl box keypair for sealed per-agent DSNs (design #10).
	// The public key goes out on /register; the private key stays on disk
	// (0600) and opens the sealed DSNs the Console delivers via /config. On
	// failure we run without a key - the Console then sends plaintext DSNs.
	keypair, err := agent.LoadOrCreateAgentKeypair(cfg.Agent.DataDir)
	if err != nil {
		slog.Warn("agent keypair unavailable — Console will send plaintext DSNs",
			"data_dir", cfg.Agent.DataDir, "error", err)
	} else {
		slog.Info("agent keypair loaded")
	}

	client := transport.NewClient(agent.ConsoleURL, cfg.Token, instanceID)

	// Buffer is best-effort — if the data dir isn't writable we log and
	// proceed without one (no buffered retries on outage, but the agent
	// still runs).
	buf, err := agent.NewEventBuffer(cfg.Agent.DataDir)
	if err != nil {
		slog.Warn("event buffer disabled (data dir not writable); set LIGHTHOUSE_DATA_DIR or agent.data_dir to a writable path",
			"data_dir", cfg.Agent.DataDir, "error", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Health probes for Kubernetes (and anything else that wants
	// /healthz/{live,ready}). Disabled when health_port is zero.
	health := agent.NewHealthState(agent.DefaultHealthLivenessThreshold)
	if cfg.Agent.HealthPort > 0 {
		addr := fmt.Sprintf(":%d", cfg.Agent.HealthPort)
		go func() {
			slog.Info("health server listening", "addr", addr)
			if err := health.RunServer(ctx, addr); err != nil {
				slog.Error("health server terminated", "error", err)
			}
		}()
	}

	// Runtime + node-name self-report (see
	// docs/victoriametrics/lighthause/PLAN.md §1.2). Runtime is the
	// signal the Console uses to auto-flip the Lighthouse to
	// allow_multi_instance on first registration of a k8s agent.
	// node_name is sent on every heartbeat to drive
	// lighthouse_active_agents for per-pod liveness.
	runtime := "bare_metal"
	if discovery.IsKubernetes() {
		runtime = "kubernetes"
	}
	// NODE_NAME is injected by the k8s downward API in the DaemonSet
	// pod spec; on bare-metal we already have the OS hostname.
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName = hostname
	}
	slog.Info("runtime self-report", "runtime", runtime, "node_name", nodeName)

	// metricHostname is the value stamped on the `host=` VictoriaMetrics
	// label for host-metrics. DaemonSet pods would otherwise default to
	// their pod hostname (os.Hostname() ⇒ e.g. "lighthouse-node-62vbx"),
	// which diverges from lighthouse_active_agents.node_name (= the
	// Kubernetes spec.nodeName, e.g. "gke-...-o779"). The Console's
	// host-filter dropdown is fed by active_agents, so picking a node
	// produced an empty chart — the label the operator selected didn't
	// exist in VM. Aligning the metric label to NODE_NAME for
	// host_metrics-only pods makes the dropdown and the chart legend
	// share one vocabulary, with no schema or relabeling layer needed.
	//
	// Scoped to role=host_metrics deliberately: a central StatefulSet
	// pod's /proc reflects the container, not the node it sits on, so
	// labelling its metrics with the node name would be misleading.
	// Bare-metal (NODE_NAME unset) and central (always uses
	// os.Hostname()) paths stay unchanged.
	metricHostname := hostname
	if cfg.Agent.IsHostMetricsOnly() && os.Getenv("NODE_NAME") != "" {
		metricHostname = os.Getenv("NODE_NAME")
	}

	// Register, then initial sync. Both must succeed before we start
	// heartbeats and check scheduling.
	registerCtx, registerCancel := context.WithTimeout(ctx, 30*time.Second)
	regReq := transport.RegisterRequest{
		AgentVersion:  agent.AgentVersion,
		AgentHostname: hostname,
		Runtime:       runtime,
		Role:          cfg.Agent.Role,
	}
	if keypair != nil {
		regReq.AgentPublicKey = keypair.PublicKeyBase64()
	}
	regResp, err := client.Register(registerCtx, regReq)
	registerCancel()
	if err != nil {
		if errors.Is(err, transport.ErrLighthouseGone) {
			slog.Info("lighthouse deleted on Console; exiting cleanly")
			return
		}
		slog.Error("register failed", "error", err)
		os.Exit(1)
	}
	slog.Info("registered",
		"lighthouse_id", regResp.LighthouseID,
		"name", regResp.Name,
		"heartbeat_interval", regResp.HeartbeatInterval(),
		"flap_threshold", regResp.FlapProtectionThreshold,
		"check_count", len(regResp.Checks),
	)

	health.MarkReady()

	// Wrap the protocol-dispatching executor in the logging decorator. At
	// the default info level these logs are silent; flipping
	// agent.log_level=debug surfaces redacted check inputs/outputs for
	// troubleshooting (per design §11).
	// Check traces (status-harbor docs/eBPF/11-traces.md): spans per check
	// run, sent while the Console's traces gate has them on.
	traceExporter := traces.NewExporter(agent.ConsoleURL, cfg.Token,
		&http.Client{Timeout: 30 * time.Second, Transport: transport.NewAgentTransport()})
	checkTracer := traces.NewCheckTracer(traceExporter, metricHostname)
	// The eBPF series' host label, so OBI spans join the map's flows.
	tracesPipeline := traces.NewPipeline(traceExporter, nodeName, 5)
	checkTracer.OnStart = tracesPipeline.MarkCheck
	go traceExporter.Run(ctx)
	go tracesPipeline.Run(ctx)
	executor := agent.NewLoggingExecutor(newRealExecutor(checkTracer), nil)
	r := agent.NewRunner(cfg, client, executor, nodeName, hostname)
	r.SetTracesGate(func(g *transport.TracesGate) {
		checkTracer.SetEnabled(g != nil && g.Checks)
		if g == nil {
			tracesPipeline.SetGate(false, 0, 100)
			return
		}
		sample := 100
		if g.SamplePercent != nil {
			sample = *g.SamplePercent
		}
		tracesPipeline.SetGate(g.Services, g.SpansPerSecond, sample)
	})
	r.ApplyTracesGate(regResp.Traces)
	if buf != nil {
		r.SetBuffer(buf)
	}
	r.SetHealthState(health)
	r.SetEtag(regResp.ConfigEtag)

	// eBPF collectors (docs/eBPF/01-foundation.md). Nil manager on the
	// central pod on Kubernetes and off Linux. Collectors start only when
	// the Console's ebpf gate names them; LIGHTHOUSE_EBPF=off overrides.
	ebpfManager, ebpfC, ebpfBatcher := agent.NewEBPF(ctx, cfg, discovery.IsKubernetes(), func(ctx context.Context, events []transport.EBPFEnvelope) error {
		_, err := client.SendEBPFEvents(ctx, transport.EBPFEventsRequest{Events: events})
		return err
	}, nodeName, r.Checks, tracesPipeline)
	if ebpfManager != nil {
		r.SetEBPF(ebpfManager)
		r.SetTracesPipeline(tracesPipeline)
		r.ApplyEBPFGate(regResp.EBPF)
		defer ebpfManager.Stop()
		go ebpfBatcher.Run(ctx)
	}
	r.ApplyConfig(
		agent.CheckDefsFromTransport(regResp.Checks),
		regResp.FlapProtectionThreshold,
		regResp.Paused,
	)

	// Initial sync (per design §7.3 step 3-4): one observation per check,
	// posted with sync_kind="initial".
	syncCtx, syncCancel := context.WithTimeout(ctx, 60*time.Second)
	if err := r.RunInitialSync(syncCtx, r.Checks()); err != nil {
		slog.Warn("initial sync failed; will recover via subsequent heartbeats",
			"error", err)
	}
	syncCancel()

	hostMetricsOnly := cfg.Agent.IsHostMetricsOnly()
	if hostMetricsOnly {
		slog.Info("agent role is host_metrics — skipping check scheduler + discovery watcher",
			"role", cfg.Agent.Role)
	}

	// Databases collector. CENTRAL role only - the host_metrics DaemonSet
	// has one pod per k8s node, and letting all of them collect would hit
	// the customer DB N times. Gating to the single central Deployment pod
	// (same owner as checks + discovery) means exactly one collector, and
	// on a node drop k8s reschedules that pod under the same lighthouse_id
	// so collection resumes automatically - no cross-lighthouse failover
	// needed for the common topology. The Console gate carries the node
	// DSNs (Option B - no local config) and drives live plan flips.
	if !hostMetricsOnly {
		// Only hand the controller an opener when we actually have a key -
		// a nil *AgentKeypair wrapped in the interface would be non-nil and
		// panic on use, so pass a nil interface instead.
		var dsnOpener database.SealedDSNOpener
		if keypair != nil {
			dsnOpener = keypair
		}
		dbController := database.NewController(client, agent.AgentVersion, dsnOpener)
		r.SetDatabaseGateHandler(dbController.ApplyGate)
		// Register carries only the enabled flag; fetch the cluster+DSN
		// payload from /config when enabled (same path as each heartbeat).
		r.ApplyDatabaseGate(ctx, regResp.Databases, regResp.ConfigEtag)
		defer dbController.Stop()
	}

	// Optional Kubernetes Ingress discovery. Enabled via the
	// `discovery.enabled` config field (or LIGHTHOUSE_DISCOVERY_ENABLED
	// env var). Outside a cluster the watcher returns nil and we skip
	// it silently — the agent runs identically to before. The DaemonSet
	// flavour (role=host_metrics) skips discovery even when the env
	// would otherwise turn it on: the central Deployment is the single
	// owner of the discovery snapshot, and N pods racing on
	// snapshot=true would churn the table.
	if cfg.Discovery.Enabled && !hostMetricsOnly {
		w, err := discovery.NewWatcher(cfg.Discovery.Namespaces)
		switch {
		case err != nil:
			slog.Warn("discovery init failed; continuing without it", "error", err)
		case w == nil:
			slog.Info("discovery enabled but not running in a Kubernetes cluster; skipped")
		default:
			w.SendFunc = func(ctx context.Context, items []discovery.SnapshotItem) error {
				wire := make([]transport.DiscoverySnapshotItem, len(items))
				for i, it := range items {
					wire[i] = transport.DiscoverySnapshotItem{
						Kind:         it.Kind,
						Namespace:    it.Namespace,
						ResourceName: it.ResourceName,
						Host:         it.Host,
						Path:         it.Path,
						Port:         it.Port,
						Protocol:     it.Protocol,
					}
				}
				_, err := client.SendDiscoveries(ctx, transport.DiscoverySnapshotRequest{
					Snapshot: true,
					Items:    wire,
				})
				return err
			}
			go w.Run(ctx)
			go discovery.RunAddressMap(ctx, cfg.Discovery.Namespaces, time.Minute, func(ctx context.Context, m []discovery.AddressEntry) error {
				items := make([]transport.K8sAddress, len(m))
				for i, e := range m {
					items[i] = transport.K8sAddress(e)
				}
				return client.SendK8sAddresses(ctx, transport.K8sAddressesRequest{Items: items})
			})
			slog.Info("discovery watcher started", "namespaces", cfg.Discovery.Namespaces)
		}
	}

	// Long-running goroutines. Heartbeat + host-metrics always run;
	// the check scheduler is opt-out for host-metrics-only pods.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := r.RunHeartbeat(ctx, regResp.HeartbeatInterval()); err != nil {
			if errors.Is(err, transport.ErrLighthouseGone) {
				slog.Info("lighthouse deleted on Console; cancelling agent")
				cancel() // bring down the scheduler goroutine and main
				return
			}
			slog.Error("heartbeat loop terminated unexpectedly", "error", err)
		}
	}()
	if !hostMetricsOnly {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.RunScheduler(ctx); err != nil {
				slog.Error("scheduler terminated unexpectedly", "error", err)
			}
		}()
	}
	// Host-metrics ticker. RunHostMetrics returns immediately if /register's
	// HostMetrics is nil (plan unsupported) or Enabled=false (team paused),
	// so the goroutine is cheap when metrics are off. Uses the same Console
	// base URL + token as the rest of the agent's transport.
	wg.Add(1)
	go func() {
		defer wg.Done()
		sender := transport.NewHTTPHostMetricsSender(transport.HTTPHostMetricsConfig{
			BaseURL:      agent.ConsoleURL,
			Token:        cfg.Token,
			LighthouseID: regResp.LighthouseID,
			Hostname:     metricHostname,
			InstanceID:   instanceID,
		})
		// Host /proc collector — bare-metal always, DaemonSet pods
		// always (they mount /host/proc via cfg.Agent.ProcRoot, plus
		// optionally the host's / at cfg.Agent.HostRoot so per-mount
		// disk stats reflect the node instead of paths that happen
		// to also exist inside the container). On non-Linux this is
		// the platform collector (sysctl / WMI / noop).
		//
		// Suppressed for the central StatefulSet pod on Kubernetes:
		// its /proc reflects the container's pid namespace, not the
		// underlying GKE node, so the host=* series it would emit
		// (cpu_busy_percent, mem_used_bytes, …) are not a meaningful
		// view of anything an operator wants — neither the node
		// (DaemonSet pods cover that) nor anything actionable. The
		// noise also produced an empty-chart UX when an operator
		// picked "lighthouse-0" from the Metrics page's host
		// dropdown after the host=NODE_NAME alignment landed. The
		// central pod keeps doing discovery + checks + k8sstats +
		// heartbeats — only the per-host hardware readout is
		// dropped.
		var hostC agent.Collector
		if hostMetricsOnly || !discovery.IsKubernetes() {
			hostC = agent.NewLinuxCollectorWithRoots(cfg.Agent.ProcRoot, cfg.Agent.HostRoot)
		}
		// Cluster-shape collector — k8s only, central role only.
		// DaemonSet pods don't run it because N pods all listing the
		// apiserver would multiply the load. Outside a cluster
		// NewCollector returns nil; the MultiCollector compacts the
		// nil away.
		var k8sC agent.Collector
		if !hostMetricsOnly && discovery.IsKubernetes() {
			c, err := k8sstats.NewCollector()
			if err != nil {
				slog.Warn("k8sstats init failed; continuing without cluster metrics", "error", err)
			} else if c != nil {
				k8sC = c
				slog.Info("k8sstats collector started")
			}
		}
		r.RunHostMetrics(ctx, regResp.HostMetrics, agent.NewMultiCollector(hostC, k8sC, ebpfC), sender)
	}()

	<-ctx.Done()
	slog.Info("shutdown initiated")

	// Graceful teardown: stop new check runs (already done via ctx),
	// wait briefly for in-flight, flush buffer, post /shutdown.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	wg.Wait()
	_ = r.Shutdown(shutdownCtx, "sigterm")
	slog.Info("lighthouse stopped cleanly")
}

func configureLogging(level string) {
	lvl := slog.LevelInfo
	if level == "debug" {
		lvl = slog.LevelDebug
	}
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(h))
}
