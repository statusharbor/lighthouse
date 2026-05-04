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
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/statusharbor/lighthouse/internal/agent"
	"github.com/statusharbor/lighthouse/internal/transport"
)

var (
	configPath = flag.String("config", "lighthouse.yaml", "path to lighthouse.yaml")
)

func main() {
	flag.Parse()

	cfg, err := agent.LoadFile(*configPath)
	if err != nil {
		slog.Error("config load failed", "path", *configPath, "error", err)
		os.Exit(2)
	}
	configureLogging(cfg.Agent.LogLevel)

	hostname, _ := os.Hostname()
	slog.Info("lighthouse starting",
		"version", agent.AgentVersion,
		"hostname", hostname,
		"data_dir", cfg.Agent.DataDir,
	)

	client := transport.NewClient(agent.ConsoleURL, cfg.Token)

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

	// Register, then initial sync. Both must succeed before we start
	// heartbeats and check scheduling.
	registerCtx, registerCancel := context.WithTimeout(ctx, 30*time.Second)
	regResp, err := client.Register(registerCtx, transport.RegisterRequest{
		AgentVersion:  agent.AgentVersion,
		AgentHostname: hostname,
	})
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
	executor := agent.NewLoggingExecutor(newRealExecutor(), nil)
	r := agent.NewRunner(cfg, client, executor)
	if buf != nil {
		r.SetBuffer(buf)
	}
	r.SetHealthState(health)
	r.SetEtag(regResp.ConfigEtag)
	r.ApplyConfig(
		agent.CheckDefsFromTransport(regResp.Checks),
		regResp.FlapProtectionThreshold,
		regResp.Paused,
	)

	// Initial sync (per design §7.3 step 3-4): one observation per check,
	// posted as is_initial_sync=true.
	syncCtx, syncCancel := context.WithTimeout(ctx, 60*time.Second)
	if err := r.RunInitialSync(syncCtx, r.Checks()); err != nil {
		slog.Warn("initial sync failed; will recover via subsequent heartbeats",
			"error", err)
	}
	syncCancel()

	// Long-running goroutines.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := r.RunHeartbeat(ctx, regResp.HeartbeatInterval()); err != nil {
			if errors.Is(err, transport.ErrLighthouseGone) {
				slog.Info("lighthouse deleted on Console; cancelling agent")
				cancel() // bring down the scheduler goroutine
				return
			}
			slog.Error("heartbeat loop terminated unexpectedly", "error", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := r.RunScheduler(ctx); err != nil {
			slog.Error("scheduler terminated unexpectedly", "error", err)
		}
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
